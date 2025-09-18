import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, requireAuth, requireAdmin } from "./auth";
import { bogPaymentService, BOGCreateOrderRequest } from "./bogPayment";
import { 
  insertProductSchema,
  insertCartItemSchema,
  insertOrderSchema,
  insertOrderItemSchema,
  insertNewsletterSchema,
  insertContactMessageSchema
} from "../shared/schema";
import { sendOrderNotificationEmail, sendOrderConfirmationToCustomer } from './email';

// Helper function to build language-aware URLs
function buildLanguageAwareURL(baseUrl: string, path: string, language?: string): string {
  if (language === 'en') {
    return `${baseUrl}/en${path}`;
  }
  return `${baseUrl}${path}`;
}

// Helper function to configure BOG payment options
function getBOGPaymentConfig(paymentMethod: string, totalAmount: number): { 
  payment_method: string[], 
  bnpl?: boolean,
  config?: {
    loan?: {
      type?: string;
      month?: number;
    };
  };
} {
  switch (paymentMethod) {
    case 'card':
      // Card payment includes all available payment methods on BOG gateway
      return { 
        payment_method: ['card', 'google_pay', 'apple_pay', 'bog_p2p', 'bog_loyalty'] 
      };
    case 'installment':
      return { 
        payment_method: ['bnpl'], // Use bnpl payment method
        bnpl: false, // Show only standard installment plan
        config: {
          loan: {
            type: undefined, // Discount code from BOG calculator (undefined for no discount)
            month: 12 // 12-month installment plan
          }
        }
      };
    case 'bnpl':
      return { 
        payment_method: ['bnpl'], // Use bnpl payment method
        bnpl: true, // Show only payment in installments (part-by-part)
        config: {
          loan: {
            type: undefined, // Discount code from BOG calculator (undefined for no discount)
            month: 6 // 6-month part-by-part plan
          }
        }
      };
    default:
      return { payment_method: ['card'] };
  }
}

// --- SEO helpers ---
function slugify(input: string): string {
  return input
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-');
}

function renderSeoHtml(page: any, baseUrl: string): string {
  const title = page.metaTitle || page.title;
  const description = page.metaDescription || '';
  const canonical = page.canonicalUrl || `${baseUrl}/seo/${page.slug}`;
  const jsonLd = page.jsonLd ? `<script type="application/ld+json">${JSON.stringify(page.jsonLd)}</script>` : '';
  return `<!doctype html>
  <html lang="${page.language || 'en'}">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${title}</title>
      <meta name="description" content="${description}" />
      <link rel="canonical" href="${canonical}" />
      ${jsonLd}
    </head>
    <body>
      <main>
        ${page.contentHtml}
      </main>
    </body>
  </html>`;
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup custom authentication
  setupAuth(app);

  // Product routes
  app.get("/api/products", async (req, res) => {
    try {
      const products = await storage.getProducts();
      res.json(products);
    } catch (error) {
      console.error("Error fetching products:", error);
      res.status(500).json({ message: "Failed to fetch products" });
    }
  });

  // Get individual product by ID
  app.get("/api/products/:id", async (req, res) => {
    try {
      const product = await storage.getProductById(req.params.id);
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.json(product);
    } catch (error) {
      console.error("Error fetching product:", error);
      res.status(500).json({ message: "Failed to fetch product" });
    }
  });

  // Admin product routes
  app.get("/api/admin/products", requireAdmin, async (req, res) => {
    try {
      const products = await storage.getProducts();
      res.json(products);
    } catch (error) {
      console.error("Error fetching products for admin:", error);
      res.status(500).json({ message: "Failed to fetch products" });
    }
  });

  app.post("/api/admin/products", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertProductSchema.parse(req.body);
      const product = await storage.createProduct(validatedData);
      res.status(201).json(product);
    } catch (error) {
      console.error("Error creating product:", error);
      res.status(400).json({ message: "Failed to create product", error: (error as Error).message });
    }
  });

  app.put("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const validatedData = insertProductSchema.partial().parse(req.body);
      const product = await storage.updateProduct(id, validatedData);
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.json(product);
    } catch (error) {
      console.error("Error updating product:", error);
      res.status(400).json({ message: "Failed to update product", error: (error as Error).message });
    }
  });

  app.delete("/api/admin/products/:id", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const success = await storage.deleteProduct(id);
      if (!success) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ 
        message: "Failed to delete product",
        error: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });

  // Bulk pricing management routes
  app.post("/api/admin/products/bulk-pricing", requireAdmin, async (req, res) => {
    try {
      const { productIds, discountPercentage } = req.body;
      
      if (!Array.isArray(productIds) || productIds.length === 0) {
        return res.status(400).json({ message: "Product IDs array is required" });
      }
      
      if (typeof discountPercentage !== 'number' || discountPercentage < 0 || discountPercentage > 100) {
        return res.status(400).json({ message: "Discount percentage must be between 0 and 100" });
      }
      
      const updatedProducts = await storage.bulkUpdateProductPricing(productIds, discountPercentage);
      res.json({ 
        message: `Successfully updated pricing for ${updatedProducts.length} products`,
        updatedProducts 
      });
    } catch (error) {
      console.error("Error updating bulk pricing:", error);
      res.status(500).json({ message: "Failed to update bulk pricing" });
    }
  });

  app.post("/api/admin/products/reset-discounts", requireAdmin, async (req, res) => {
    try {
      const resetProducts = await storage.resetAllProductDiscounts();
      res.json({ 
        message: `Successfully reset discounts for ${resetProducts.length} products`,
        resetProducts 
      });
    } catch (error) {
      console.error("Error resetting discounts:", error);
      res.status(500).json({ message: "Failed to reset discounts" });
    }
  });

  app.get("/api/products/:id", async (req, res) => {
    try {
      const product = await storage.getProduct(req.params.id);
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }
      res.json(product);
    } catch (error) {
      console.error("Error fetching product:", error);
      res.status(500).json({ message: "Failed to fetch product" });
    }
  });

  // Cart routes - Support both authenticated and unauthenticated users
  app.get("/api/cart", async (req: any, res) => {
    try {
      // For unauthenticated users, return session cart
      if (!(req.session as any).userId) {
        const sessionCart = (req.session as any).cart || [];
        // Convert session cart to proper format with product details
        const cartWithProducts = [];
        for (const item of sessionCart) {
          const product = await storage.getProduct(item.productId);
          if (product) {
            cartWithProducts.push({
              id: item.id,
              userId: null,
              productId: item.productId,
              quantity: item.quantity,
              createdAt: new Date(),
              product
            });
          }
        }
        return res.json(cartWithProducts);
      }
      
      // For authenticated users, get cart from database
      const userId = (req.session as any).userId;
      const cartItems = await storage.getCartItems(userId);
      res.json(cartItems);
    } catch (error) {
      console.error("Error fetching cart:", error);
      res.status(500).json({ message: "Failed to fetch cart" });
    }
  });

  app.post("/api/cart", async (req: any, res) => {
    try {
      const { productId, quantity = 1 } = req.body;
      
      // For unauthenticated users, store in session
      if (!(req.session as any).userId) {
        if (!(req.session as any).cart) {
          (req.session as any).cart = [];
        }
        
        const sessionCart = (req.session as any).cart;
        const existingItem = sessionCart.find((item: any) => item.productId === productId);
        
        if (existingItem) {
          existingItem.quantity += quantity;
        } else {
          sessionCart.push({
            id: `session_${Date.now()}_${Math.random()}`,
            productId,
            quantity
          });
        }
        
        const product = await storage.getProduct(productId);
        const cartItem = {
          id: existingItem?.id || sessionCart[sessionCart.length - 1].id,
          userId: null,
          productId,
          quantity: existingItem ? existingItem.quantity : quantity,
          createdAt: new Date(),
          product
        };
        
        return res.json(cartItem);
      }
      
      // For authenticated users, store in database
      const userId = (req.session as any).userId;
      const cartItemData = insertCartItemSchema.parse({
        productId,
        quantity,
        userId
      });
      const cartItem = await storage.addToCart(cartItemData);
      res.json(cartItem);
    } catch (error) {
      console.error("Error adding to cart:", error);
      res.status(500).json({ message: "Failed to add to cart" });
    }
  });

  app.put("/api/cart/:id", async (req: any, res) => {
    try {
      const { quantity } = req.body;
      const itemId = req.params.id;
      
      // For unauthenticated users, update session cart
      if (!(req.session as any).userId) {
        const sessionCart = (req.session as any).cart || [];
        const item = sessionCart.find((item: any) => item.id === itemId);
        if (item) {
          item.quantity = quantity;
          const product = await storage.getProduct(item.productId);
          return res.json({
            id: item.id,
            userId: null,
            productId: item.productId,
            quantity: item.quantity,
            createdAt: new Date(),
            product
          });
        }
        return res.status(404).json({ message: "Item not found" });
      }
      
      // For authenticated users, update database
      const cartItem = await storage.updateCartItem(itemId, quantity);
      res.json(cartItem);
    } catch (error) {
      console.error("Error updating cart item:", error);
      res.status(500).json({ message: "Failed to update cart item" });
    }
  });

  app.delete("/api/cart/:id", async (req: any, res) => {
    try {
      const itemId = req.params.id;
      
      // For unauthenticated users, remove from session cart
      if (!(req.session as any).userId) {
        const sessionCart = (req.session as any).cart || [];
        const index = sessionCart.findIndex((item: any) => item.id === itemId);
        if (index > -1) {
          sessionCart.splice(index, 1);
        }
        return res.json({ message: "Item removed from cart" });
      }
      
      // For authenticated users, remove from database
      await storage.removeFromCart(itemId);
      res.json({ message: "Item removed from cart" });
    } catch (error) {
      console.error("Error removing from cart:", error);
      res.status(500).json({ message: "Failed to remove from cart" });
    }
  });

  app.delete("/api/cart", async (req: any, res) => {
    try {
      // For unauthenticated users, clear session cart
      if (!(req.session as any).userId) {
        (req.session as any).cart = [];
        return res.json({ message: "Cart cleared" });
      }
      
      // For authenticated users, clear database cart
      const userId = (req.session as any).userId;
      await storage.clearCart(userId);
      res.json({ message: "Cart cleared" });
    } catch (error) {
      console.error("Error clearing cart:", error);
      res.status(500).json({ message: "Failed to clear cart" });
    }
  });

  // BOG Payment with Calculator Results
  app.post("/api/payments/initiate-with-calculator", async (req: any, res) => {
    try {
      const userId = (req.session as any).userId || null;
      const { shippingAddress, billingAddress, items, calculatorResult, paymentMethod, language } = req.body;
      
      // Calculate total with discounts
      let total = 0;
      const orderItems = [];
      
      for (const item of items) {
        const product = await storage.getProduct(item.productId);
        if (!product) {
          return res.status(400).json({ message: `Product ${item.productId} not found` });
        }
        
        // Calculate price with discount if applicable
        const basePrice = parseFloat(product.price);
        const discountedPrice = product.discountPercentage && product.discountPercentage > 0 
          ? basePrice * (1 - product.discountPercentage / 100)
          : basePrice;
        
        const itemTotal = discountedPrice * item.quantity;
        total += itemTotal;
        
        orderItems.push({
          productId: item.productId,
          quantity: item.quantity,
          price: discountedPrice.toString()
        });
      }

      // Create order with pending payment status
      const orderData = insertOrderSchema.parse({
        userId,
        total: total.toString(),
        shippingAddress,
        billingAddress,
        paymentStatus: "pending"
      });

      const order = await storage.createOrder(orderData, orderItems as any);

      // Create BOG payment order using calculator results
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      
      // BOG API configuration based on payment method type
      let paymentConfig: any = {};
      
      if (paymentMethod === 'bnpl') {
        // For Buy Now Pay Later (part-by-part) - use bnpl method with type "zero"
        paymentConfig = {
          payment_method: ['bnpl'],
          bnpl: true,
          config: {
            loan: {
              type: calculatorResult.discount_code || 'zero',
              month: calculatorResult.month || 6
            }
          }
        };
      } else {
        // For standard installments - use bog_loan method with type "standard"
        paymentConfig = {
          payment_method: ['bog_loan'],  // Use bog_loan for standard installments
          config: {
            loan: {
              type: calculatorResult.discount_code || 'standard',
              month: calculatorResult.month || 12
            }
          }
        };
      }
      
      console.log(`Using BOG Calculator: ${calculatorResult.month} months (${paymentMethod}), payment_method: ${paymentMethod === 'bnpl' ? 'bnpl' : 'bog_loan'}`);

      const bogOrderRequest: BOGCreateOrderRequest = {
        callback_url: `${baseUrl}/api/payments/callback`,
        external_order_id: order.id,
        purchase_units: {
          currency: 'GEL',
          total_amount: parseFloat(total.toFixed(2)), // Keep as lari with decimal precision
          basket: orderItems.map((item) => ({
            product_id: item.productId,
            description: `Product ${item.productId}`,
            quantity: item.quantity,
            unit_price: parseFloat(parseFloat(item.price).toFixed(2)), // Keep as lari with decimal precision
            total_price: parseFloat((item.quantity * parseFloat(item.price)).toFixed(2)) // Keep as lari with decimal precision
          }))
        },
        redirect_urls: {
          success: buildLanguageAwareURL(baseUrl, `/payment-success?orderCode=${order.orderCode}`, language),
          fail: buildLanguageAwareURL(baseUrl, `/payment-cancel`, language)
        },
        ttl: 60,
        ...paymentConfig,
        capture: 'automatic',
        application_type: 'web'
      };

      console.log(`Creating BOG order with calculator result:`, calculatorResult);
      console.log("BOG Order Request:", JSON.stringify(bogOrderRequest, null, 2));

      const bogOrder = await bogPaymentService.createOrder(bogOrderRequest);
      console.log("BOG Order Response:", JSON.stringify(bogOrder, null, 2));
      
      await storage.updateOrderPayment(order.id, bogOrder.id, 'pending');
      
      const paymentUrl = bogPaymentService.getPaymentUrl(bogOrder);
      
      const response = {
        orderId: order.id,
        paymentId: bogOrder.id,
        paymentUrl,
        status: 'created'
      };
      
      res.json(response);
    } catch (error) {
      console.error("Error initiating calculator payment:", error);
      res.status(500).json({ message: "Failed to initiate payment" });
    }
  });

  // Payment initiation route (for card payments only)
  app.post("/api/payments/initiate", async (req: any, res) => {
    try {
      const userId = (req.session as any).userId || null;
      const { shippingAddress, billingAddress, items, paymentMethod = 'card', language } = req.body;
      
      // Calculate total with discounts
      let total = 0;
      const orderItems = [];
      
      for (const item of items) {
        const product = await storage.getProduct(item.productId);
        if (!product) {
          return res.status(400).json({ message: `Product ${item.productId} not found` });
        }
        
        // Calculate price with discount if applicable
        const basePrice = parseFloat(product.price);
        const discountedPrice = product.discountPercentage && product.discountPercentage > 0 
          ? basePrice * (1 - product.discountPercentage / 100)
          : basePrice;
        
        const itemTotal = discountedPrice * item.quantity;
        total += itemTotal;
        
        orderItems.push({
          productId: item.productId,
          quantity: item.quantity,
          price: discountedPrice.toString()
        });
      }

      // Create order with pending payment status
      const orderData = insertOrderSchema.parse({
        userId,
        total: total.toString(),
        shippingAddress,
        billingAddress,
        paymentStatus: "pending"
      });

      const order = await storage.createOrder(orderData, orderItems as any);

      // Create BOG payment order using official BOG Payment API
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const paymentConfig = getBOGPaymentConfig(paymentMethod, total);
      const bogOrderRequest: BOGCreateOrderRequest = {
        callback_url: `${baseUrl}/api/payments/callback`,
        external_order_id: order.id,
        purchase_units: {
          currency: 'GEL',
          total_amount: parseFloat(total.toFixed(2)), // Keep as lari with decimal precision
          basket: orderItems.map((item) => ({
            product_id: item.productId,
            description: `Product ${item.productId}`, // You might want to get actual product name
            quantity: item.quantity,
            unit_price: parseFloat(parseFloat(item.price).toFixed(2)), // Keep as lari with decimal precision
            total_price: parseFloat((item.quantity * parseFloat(item.price)).toFixed(2)) // Keep as lari with decimal precision
          }))
        },
        redirect_urls: {
          success: buildLanguageAwareURL(baseUrl, `/payment-success?orderCode=${order.orderCode}`, language),
          fail: buildLanguageAwareURL(baseUrl, `/payment-cancel`, language)
        },
        ttl: 60, // 60 minutes to complete payment
        ...paymentConfig, // Set payment method and bnpl config
        capture: 'automatic', // Immediate capture
        application_type: 'web'
      };

      // Debug: Log the complete BOG order request
      console.log(`Creating BOG order for payment method: ${paymentMethod}`);
      console.log("BOG Order Request:", JSON.stringify(bogOrderRequest, null, 2));

      // Create BOG order (using real BOG Payment API)
      const bogOrder = await bogPaymentService.createOrder(bogOrderRequest);
      console.log("BOG Order Response:", JSON.stringify(bogOrder, null, 2));
      
      // Update order with payment ID
      await storage.updateOrderPayment(order.id, bogOrder.id, 'pending');
      
      const paymentUrl = bogPaymentService.getPaymentUrl(bogOrder);
      console.log("Generated Payment URL:", paymentUrl);
      
      const response = {
        orderId: order.id,
        paymentId: bogOrder.id,
        paymentUrl,
        status: 'created'
      };
      
      console.log("Sending response to frontend:", JSON.stringify(response, null, 2));
      res.json(response);
    } catch (error) {
      console.error("Error initiating payment:", error);
      res.status(500).json({ message: "Failed to initiate payment" });
    }
  });

  // BOG Payment callback (webhook)
  app.post("/api/payments/callback", async (req, res) => {
    try {
      console.log("BOG Payment callback received:", req.body);
      
      // Handle the actual BOG callback structure
      const { body } = req.body;
      
      if (body && body.external_order_id && body.order_status) {
        const externalOrderId = body.external_order_id; // This is our order ID
        const bogOrderId = body.order_id; // BOG's order ID
        const orderStatus = body.order_status.key; // 'completed', 'failed', etc.
        
        // Update order payment status based on BOG callback
        const mappedOrderStatus = orderStatus === 'completed' ? 'confirmed' : orderStatus === 'failed' ? 'cancelled' : 'pending';
        const mappedPaymentStatus = orderStatus === 'completed' ? 'completed' : orderStatus === 'failed' ? 'failed' : 'pending';
        
        console.log(`Updating order ${externalOrderId} with status: ${mappedOrderStatus}, payment: ${mappedPaymentStatus}`);
        
        await storage.updateOrderPayment(externalOrderId, bogOrderId, mappedPaymentStatus);
        await storage.updateOrderStatus(externalOrderId, mappedOrderStatus, mappedPaymentStatus);
        
        // Clear cart after successful payment and send emails
        if (orderStatus === 'completed') {
          const order = await storage.getOrder(externalOrderId);
          if (order) {
            // Clear cart for authenticated users
            if (order.userId) {
              await storage.clearCart(order.userId);
            }
            
            // Send email notifications for both authenticated and guest orders
            try {
              const orderWithItems = await storage.getOrderByCode(order.orderCode);
              if (orderWithItems?.orderItems) {
                let customerName = 'Guest Customer';
                let customerEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER || 'admin@velfrance.ge'; // For guest orders, send customer email to admin
                
                // For authenticated users, get their info
                if (order.userId) {
                  const user = await storage.getUser(order.userId);
                  if (user) {
                    customerName = user.firstName || user.lastName ? `${user.firstName || ''} ${user.lastName || ''}`.trim() : user.email;
                    customerEmail = user.email;
                  }
                }
                
                const emailData = {
                  orderId: order.orderCode,
                  customerName,
                  customerEmail,
                  totalAmount: parseFloat(order.total),
                  items: orderWithItems.orderItems.map((item: any) => ({
                    productName: item.product?.name || `Product ${item.productId}`,
                    quantity: item.quantity,
                    price: parseFloat(item.price)
                  })),
                  shippingAddress: order.shippingAddress,
                  paymentMethod: 'BOG Payment Gateway'
                };
                
                // Always send notification to admin
                console.log('Sending order notification emails for order:', order.orderCode, '(User ID:', order.userId || 'Guest', ')');
                const adminEmailResult = await sendOrderNotificationEmail(emailData);
                console.log('Admin email sent:', adminEmailResult);
                
                // Send confirmation to customer only for authenticated users
                if (order.userId && customerEmail !== (process.env.ADMIN_EMAIL || process.env.EMAIL_USER)) {
                  const customerEmailResult = await sendOrderConfirmationToCustomer(emailData);
                  console.log('Customer email sent:', customerEmailResult);
                } else {
                  console.log('Guest order - customer confirmation email skipped');
                }
              }
            } catch (emailError) {
              console.error('Failed to send order emails:', emailError);
              // Don't fail the order if email fails
            }
          }
        }
      }
      
      // Always respond with 200 OK to acknowledge receipt
      res.status(200).json({ received: true });
    } catch (error) {
      console.error("Error processing BOG callback:", error);
      res.status(200).json({ received: true }); // Still acknowledge to prevent retries
    }
  });

  // Payment success callback
  app.get("/api/payments/success", async (req, res) => {
    try {
      const { orderId, paymentId } = req.query;
      
      if (!orderId || !paymentId) {
        return res.status(400).json({ message: "Missing orderId or paymentId" });
      }

      // Note: BOG payment status checking would require additional API call
      // For now, we'll rely on the callback for status updates
      console.log("Payment success callback received for:", orderId, paymentId);
      
      // Update order as successful since we reached the success callback
      let orderStatus = 'confirmed';
      let paymentStatus = 'completed';
      
      // Clear user's cart after successful payment and send emails
      const order = await storage.getOrder(orderId as string);
      if (order) {
        // Clear cart for authenticated users
        if (order.userId) {
          await storage.clearCart(order.userId);
        }
        
        // Send email notifications for both authenticated and guest orders
        try {
          const orderWithItems = await storage.getOrderByCode(order.orderCode);
          if (orderWithItems?.orderItems) {
            let customerName = 'Guest Customer';
            let customerEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER || 'admin@velfrance.ge'; // For guest orders, send customer email to admin
            
            // For authenticated users, get their info
            if (order.userId) {
              const user = await storage.getUser(order.userId);
              if (user) {
                customerName = user.firstName || user.lastName ? `${user.firstName || ''} ${user.lastName || ''}`.trim() : user.email;
                customerEmail = user.email;
              }
            }
            
            const emailData = {
              orderId: order.orderCode,
              customerName,
              customerEmail,
              totalAmount: parseFloat(order.total),
              items: orderWithItems.orderItems.map((item: any) => ({
                productName: item.product?.name || `Product ${item.productId}`,
                quantity: item.quantity,
                price: parseFloat(item.price)
              })),
              shippingAddress: order.shippingAddress,
              paymentMethod: 'BOG Payment Gateway'
            };
            
            // Always send notification to admin
            console.log('Sending order notification emails for order:', order.orderCode, '(User ID:', order.userId || 'Guest', ')');
            const adminEmailResult = await sendOrderNotificationEmail(emailData);
            console.log('Admin email sent:', adminEmailResult);
            
            // Send confirmation to customer only for authenticated users
            if (order.userId && customerEmail !== (process.env.ADMIN_EMAIL || process.env.EMAIL_USER)) {
              const customerEmailResult = await sendOrderConfirmationToCustomer(emailData);
              console.log('Customer email sent:', customerEmailResult);
            } else {
              console.log('Guest order - customer confirmation email skipped');
            }
          }
        } catch (emailError) {
          console.error('Failed to send order emails:', emailError);
          // Don't fail the order if email fails
        }
      }
      
      await storage.updateOrderStatus(orderId as string, orderStatus, paymentStatus);
      
      // Get the updated order to retrieve the order code
      const updatedOrder = await storage.getOrder(orderId as string);
      
      // Redirect to unique order page with order code
      res.redirect(`/order/${updatedOrder?.orderCode || orderId}`);
    } catch (error) {
      console.error("Error handling payment success:", error);
      res.redirect(`/?payment=error`);
    }
  });

  // Payment cancel callback
  app.get("/api/payments/cancel", async (req, res) => {
    try {
      const { orderId } = req.query;
      
      if (orderId) {
        await storage.updateOrderStatus(orderId as string, 'cancelled', 'cancelled');
      }
      
      res.redirect(`/?payment=cancelled&orderId=${orderId}`);
    } catch (error) {
      console.error("Error handling payment cancellation:", error);
      res.redirect(`/?payment=error`);
    }
  });

  // Order routes
  app.post("/api/orders", requireAuth, async (req: any, res) => {
    try {
      const userId = (req.session as any).userId;
      const { shippingAddress, billingAddress, items } = req.body;
      
      // Calculate total
      let total = 0;
      const orderItems = [];
      
      for (const item of items) {
        const product = await storage.getProduct(item.productId);
        if (!product) {
          return res.status(400).json({ message: `Product ${item.productId} not found` });
        }
        
        const itemTotal = parseFloat(product.price) * item.quantity;
        total += itemTotal;
        
        orderItems.push({
          productId: item.productId,
          quantity: item.quantity,
          price: product.price
        });
      }

      const orderData = insertOrderSchema.parse({
        userId,
        total: total.toString(),
        shippingAddress,
        billingAddress
      });

      const order = await storage.createOrder(orderData, orderItems as any);
      
      // Clear cart after successful order
      await storage.clearCart(userId);
      
      res.json(order);
    } catch (error) {
      console.error("Error creating order:", error);
      res.status(500).json({ message: "Failed to create order" });
    }
  });

  app.get("/api/orders", requireAuth, async (req: any, res) => {
    try {
      const userId = (req.session as any).userId;
      const orders = await storage.getOrders(userId);
      res.json(orders);
    } catch (error) {
      console.error("Error fetching orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });

  // Public order route by order code (for unique URLs)
  app.get("/api/orders/code/:orderCode", async (req, res) => {
    try {
      const orderCode = req.params.orderCode;
      
      const order = await storage.getOrderByCode(orderCode);
      if (!order) {
        return res.status(404).json({ message: "Order not found" });
      }
      
      res.json(order);
    } catch (error) {
      console.error("Error fetching order by code:", error);
      res.status(500).json({ message: "Failed to fetch order" });
    }
  });

  // Admin order management routes
  app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
      const orders = await storage.getAllOrders();
      res.json(orders);
    } catch (error) {
      console.error("Error fetching all orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });

  app.get("/api/admin/orders/:id", requireAdmin, async (req, res) => {
    try {
      const order = await storage.getOrder(req.params.id);
      if (!order) {
        return res.status(404).json({ message: "Order not found" });
      }
      res.json(order);
    } catch (error) {
      console.error("Error fetching order:", error);
      res.status(500).json({ message: "Failed to fetch order" });
    }
  });

  app.patch("/api/admin/orders/:id/status", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { status, paymentStatus } = req.body;
      
      if (!status) {
        return res.status(400).json({ message: "Status is required" });
      }

      await storage.updateOrderStatus(id, status, paymentStatus || status);
      
      const updatedOrder = await storage.getOrder(id);
      res.json(updatedOrder);
    } catch (error) {
      console.error("Error updating order status:", error);
      res.status(500).json({ message: "Failed to update order status" });
    }
  });

  app.delete("/api/admin/orders/:id", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const success = await storage.deleteOrder(id);
      if (!success) {
        return res.status(404).json({ message: "Order not found" });
      }
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting order:", error);
      res.status(500).json({ message: "Failed to delete order" });
    }
  });

  // Admin order routes
  app.get("/api/admin/orders", requireAdmin, async (req: any, res) => {
    try {
      const userId = (req.session as any).userId;
      const user = await storage.getUser(userId);
      
      if (!user?.isAdmin) {
        return res.status(403).json({ message: "Admin access required" });
      }

      const orders = await storage.getAllOrders();
      res.json(orders);
    } catch (error) {
      console.error("Error fetching all orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });

  app.put("/api/admin/orders/:id/status", requireAdmin, async (req: any, res) => {
    try {
      const userId = (req.session as any).userId;
      const user = await storage.getUser(userId);
      
      if (!user?.isAdmin) {
        return res.status(403).json({ message: "Admin access required" });
      }

      const { status } = req.body;
      const order = await storage.updateOrderStatus(req.params.id, status);
      res.json(order);
    } catch (error) {
      console.error("Error updating order status:", error);
      res.status(500).json({ message: "Failed to update order status" });
    }
  });

  // Newsletter routes
  app.post("/api/newsletter", async (req, res) => {
    try {
      const newsletterData = insertNewsletterSchema.parse(req.body);
      const subscription = await storage.subscribeNewsletter(newsletterData);
      res.json({ message: "Successfully subscribed to newsletter" });
    } catch (error) {
      console.error("Error subscribing to newsletter:", error);
      res.status(500).json({ message: "Failed to subscribe to newsletter" });
    }
  });

  // Contact routes
  app.post("/api/contact", async (req, res) => {
    try {
      const contactData = insertContactMessageSchema.parse(req.body);
      const message = await storage.createContactMessage(contactData);
      res.json({ message: "Contact message sent successfully" });
    } catch (error) {
      console.error("Error sending contact message:", error);
      res.status(500).json({ message: "Failed to send contact message" });
    }
  });

  // Admin contact routes
  app.get("/api/admin/contacts", requireAdmin, async (req: any, res) => {
    try {
      const userId = (req.session as any).userId;
      const user = await storage.getUser(userId);
      
      if (!user?.isAdmin) {
        return res.status(403).json({ message: "Admin access required" });
      }

      const messages = await storage.getContactMessages();
      res.json(messages);
    } catch (error) {
      console.error("Error fetching contact messages:", error);
      res.status(500).json({ message: "Failed to fetch contact messages" });
    }
  });

  app.put("/api/admin/contacts/:id/read", requireAdmin, async (req: any, res) => {
    try {
      const userId = (req.session as any).userId;
      const user = await storage.getUser(userId);
      
      if (!user?.isAdmin) {
        return res.status(403).json({ message: "Admin access required" });
      }

      const message = await storage.markMessageAsRead(req.params.id);
      res.json(message);
    } catch (error) {
      console.error("Error marking message as read:", error);
      res.status(500).json({ message: "Failed to mark message as read" });
    }
  });

  // Translation routes
  app.get("/api/translations", async (req, res) => {
    try {
      const translations = await storage.getAllTranslations();
      res.json(translations);
    } catch (error) {
      console.error("Error fetching translations:", error);
      res.status(500).json({ message: "Failed to fetch translations" });
    }
  });

  app.get("/api/translations/:key", async (req, res) => {
    try {
      const translation = await storage.getTranslation(req.params.key);
      if (!translation) {
        return res.status(404).json({ message: "Translation not found" });
      }
      res.json(translation);
    } catch (error) {
      console.error("Error fetching translation:", error);
      res.status(500).json({ message: "Failed to fetch translation" });
    }
  });

  // Admin translation management routes
  app.post("/api/admin/translations/bulk", requireAdmin, async (req: any, res) => {
    try {
      const { translations } = req.body;
      if (!Array.isArray(translations)) {
        return res.status(400).json({ message: "Translations must be an array" });
      }

      const results = await storage.bulkCreateTranslations(translations);
      res.json({ message: `Successfully processed ${results.length} translations`, results });
    } catch (error) {
      console.error("Error bulk creating translations:", error);
      res.status(500).json({ message: "Failed to bulk create translations" });
    }
  });

  app.put("/api/admin/translations/:key", requireAdmin, async (req: any, res) => {
    try {
      const { georgianText } = req.body;
      const translation = await storage.updateTranslation(req.params.key, georgianText || "");
      
      if (!translation) {
        return res.status(404).json({ message: "Translation not found" });
      }
      
      res.json(translation);
    } catch (error) {
      console.error("Error updating translation:", error);
      res.status(500).json({ message: "Failed to update translation" });
    }
  });

  app.post("/api/admin/translations", requireAdmin, async (req: any, res) => {
    try {
      const translationData = req.body;
      const translation = await storage.createTranslation(translationData);
      res.json(translation);
    } catch (error) {
      console.error("Error creating translation:", error);
      res.status(500).json({ message: "Failed to create translation" });
    }
  });

  // --- SEO routes (Starter) ---
  // Ingest keywords
  app.post("/api/seo/keywords/ingest", requireAdmin, async (req: any, res) => {
    try {
      const { keywords, language = 'en', country = '', intent = 'informational' } = req.body || {};
      let list: string[] = [];
      if (Array.isArray(keywords)) list = keywords;
      else if (typeof keywords === 'string') list = keywords.split(/\r?\n/).map((s: string) => s.trim()).filter(Boolean);
      if (list.length === 0) return res.status(400).json({ message: 'No keywords provided' });

      const payload = list.map(k => ({ keyword: k, language, country, intent, status: 'pending' }));
      const result = await storage.bulkInsertSeoKeywords(payload as any);
      res.json({ ingested: result.length });
    } catch (error: any) {
      console.error('Error ingesting SEO keywords:', error);
      res.status(500).json({ message: 'Failed to ingest keywords' });
    }
  });

  // Generate pages for pending keywords (simple template) and optionally publish
  app.post("/api/seo/pages/generate", requireAdmin, async (req: any, res) => {
    try {
      const { limit = 10, autopublish = false, language = 'en' } = req.body || {};
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const pending = await storage.getPendingSeoKeywords(Math.max(1, Math.min(100, limit)));
      const created: any[] = [];

      for (const kw of pending) {
        try {
          // Resolve unique slug
          let baseSlug = slugify(kw.keyword);
          if (!baseSlug) baseSlug = `kw-${kw.id.slice(0,6)}`;
          let slug = baseSlug;
          let i = 2;
          while (await storage.getSeoPageBySlug(slug)) {
            slug = `${baseSlug}-${i++}`;
          }

          const title = `${kw.keyword} — Guide`;
          const metaTitle = title;
          const metaDescription = `Everything about ${kw.keyword}. Learn key facts, tips, and best practices.`;
          const canonicalUrl = `${baseUrl}/seo/${slug}`;
          const contentHtml = `
            <article>
              <h1>${kw.keyword}</h1>
              <p>This page covers "${kw.keyword}" with practical guidance, definitions, and FAQs.</p>
              <h2>Overview</h2>
              <p>${kw.keyword} explained in simple terms for quick understanding.</p>
              <h2>Key Points</h2>
              <ul>
                <li>Definition and context for ${kw.keyword}.</li>
                <li>Actionable tips related to ${kw.keyword}.</li>
                <li>Related topics and terms.</li>
              </ul>
              <h2>FAQ</h2>
              <p><strong>What is ${kw.keyword}?</strong> A concise explanation tailored for beginners.</p>
            </article>
          `;

          const jsonLd = {
            '@context': 'https://schema.org',
            '@type': 'Article',
            headline: metaTitle,
            inLanguage: language,
            mainEntityOfPage: canonicalUrl,
            datePublished: new Date().toISOString(),
          };

          const page = await storage.createSeoPage({
            keywordId: kw.id,
            slug,
            language,
            title,
            metaTitle,
            metaDescription,
            canonicalUrl,
            contentHtml,
            jsonLd: jsonLd as any,
            status: autopublish ? 'published' : 'draft',
          } as any);

          if (autopublish) {
            await storage.publishSeoPage(page.id);
            await storage.setSeoKeywordStatus(kw.id, 'published');
          } else {
            await storage.setSeoKeywordStatus(kw.id, 'drafted');
          }

          created.push({ id: page.id, slug, status: autopublish ? 'published' : 'draft' });
        } catch (innerErr: any) {
          console.error('Failed to generate page for keyword', kw.keyword, innerErr);
          await storage.setSeoKeywordStatus(kw.id, 'error', innerErr?.message || 'unknown');
        }
      }

      res.json({ created });
    } catch (error) {
      console.error('Error generating SEO pages:', error);
      res.status(500).json({ message: 'Failed to generate pages' });
    }
  });

  // Serve SEO pages as HTML
  app.get('/seo/:slug', async (req, res) => {
    try {
      const page = await storage.getSeoPageBySlug(req.params.slug);
      if (!page || page.status !== 'published') return res.status(404).send('Not Found');
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const html = renderSeoHtml(page, baseUrl);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=600');
      return res.status(200).send(html);
    } catch (error) {
      console.error('Error serving SEO page:', error);
      return res.status(500).send('Server Error');
    }
  });

  // Sitemap XML including published SEO pages
  app.get('/api/sitemap', async (req, res) => {
    try {
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const pages = await storage.listPublishedSeoPages();
      const urls = [
        `${baseUrl}/`,
        ...pages.map((p: any) => `${baseUrl}/seo/${p.slug}`),
      ];
      const lastmods: Record<string, string> = {};
      for (const p of pages as any[]) {
        if (p.publishedAt) lastmods[`${baseUrl}/seo/${p.slug}`] = new Date(p.publishedAt).toISOString();
      }
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
      <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        ${urls.map(u => `<url><loc>${u}</loc>${lastmods[u] ? `<lastmod>${lastmods[u]}</lastmod>` : ''}</url>`).join('')}
      </urlset>`;
      res.setHeader('Content-Type', 'application/xml');
      res.status(200).send(xml);
    } catch (error) {
      console.error('Error generating sitemap:', error);
      res.status(500).send('');
    }
  });

  // Robots.txt
  app.get('/api/robots', async (req, res) => {
    try {
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const text = `User-agent: *\nAllow: /\nSitemap: ${baseUrl}/sitemap.xml\n`;
      res.setHeader('Content-Type', 'text/plain');
      res.status(200).send(text);
    } catch (error) {
      res.setHeader('Content-Type', 'text/plain');
      res.status(200).send('User-agent: *\nAllow: /');
    }
  });

  // Cron endpoint for automated generation/publishing
  app.post('/api/seo/cron', async (req, res) => {
    try {
      const headerToken = req.get('x-cron-token') || (req.query.token as string) || '';
      if (process.env.SEO_CRON_TOKEN && headerToken !== process.env.SEO_CRON_TOKEN) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      const limit = Number(process.env.SEO_CRON_LIMIT || 10);
      const language = process.env.SEO_LANGUAGE || 'en';
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      const pending = await storage.getPendingSeoKeywords(Math.max(1, Math.min(100, limit)));
      const created: any[] = [];

      for (const kw of pending) {
        try {
          let baseSlug = slugify(kw.keyword);
          if (!baseSlug) baseSlug = `kw-${kw.id.slice(0,6)}`;
          let slug = baseSlug;
          let i = 2;
          while (await storage.getSeoPageBySlug(slug)) {
            slug = `${baseSlug}-${i++}`;
          }

          const title = `${kw.keyword} — Guide`;
          const metaTitle = title;
          const metaDescription = `Everything about ${kw.keyword}. Learn key facts, tips, and best practices.`;
          const canonicalUrl = `${baseUrl}/seo/${slug}`;
          const contentHtml = `
            <article>
              <h1>${kw.keyword}</h1>
              <p>This page covers "${kw.keyword}" with practical guidance, definitions, and FAQs.</p>
              <h2>Overview</h2>
              <p>${kw.keyword} explained in simple terms for quick understanding.</p>
              <h2>Key Points</h2>
              <ul>
                <li>Definition and context for ${kw.keyword}.</li>
                <li>Actionable tips related to ${kw.keyword}.</li>
                <li>Related topics and terms.</li>
              </ul>
              <h2>FAQ</h2>
              <p><strong>What is ${kw.keyword}?</strong> A concise explanation tailored for beginners.</p>
            </article>
          `;

          const jsonLd = {
            '@context': 'https://schema.org',
            '@type': 'Article',
            headline: metaTitle,
            inLanguage: language,
            mainEntityOfPage: canonicalUrl,
            datePublished: new Date().toISOString(),
          };

          const page = await storage.createSeoPage({
            keywordId: kw.id,
            slug,
            language,
            title,
            metaTitle,
            metaDescription,
            canonicalUrl,
            contentHtml,
            jsonLd: jsonLd as any,
            status: 'published',
          } as any);

          await storage.publishSeoPage(page.id);
          await storage.setSeoKeywordStatus(kw.id, 'published');

          created.push({ id: page.id, slug, status: 'published' });
        } catch (innerErr: any) {
          console.error('Cron failed for keyword', kw.keyword, innerErr);
          await storage.setSeoKeywordStatus(kw.id, 'error', innerErr?.message || 'unknown');
        }
      }

      res.json({ created, ranAt: new Date().toISOString() });
    } catch (error) {
      console.error('Cron error:', error);
      res.status(500).json({ message: 'Cron failed' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
