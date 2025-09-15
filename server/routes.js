var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  cartItems: () => cartItems,
  cartItemsRelations: () => cartItemsRelations,
  contactMessages: () => contactMessages,
  insertCartItemSchema: () => insertCartItemSchema,
  insertContactMessageSchema: () => insertContactMessageSchema,
  insertNewsletterSchema: () => insertNewsletterSchema,
  insertOrderItemSchema: () => insertOrderItemSchema,
  insertOrderSchema: () => insertOrderSchema,
  insertProductSchema: () => insertProductSchema,
  insertTranslationSchema: () => insertTranslationSchema,
  insertUserSchema: () => insertUserSchema,
  loginSchema: () => loginSchema,
  newsletters: () => newsletters,
  orderItems: () => orderItems,
  orderItemsRelations: () => orderItemsRelations,
  orders: () => orders,
  ordersRelations: () => ordersRelations,
  products: () => products,
  productsRelations: () => productsRelations,
  registerSchema: () => registerSchema,
  sessions: () => sessions,
  translations: () => translations,
  users: () => users,
  usersRelations: () => usersRelations
});
import { sql } from "drizzle-orm";
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  integer,
  decimal,
  boolean
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";
var sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull()
  },
  (table) => [index("IDX_session_expire").on(table.expire)]
);
var users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique().notNull(),
  password: varchar("password").notNull(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  isAdmin: boolean("is_admin").default(false),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var products = pgTable("products", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description").notNull(),
  // Legacy field, kept for migration
  descriptionGeorgian: text("description_georgian"),
  // Georgian description
  descriptionEnglish: text("description_english"),
  // English description
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  discountPercentage: integer("discount_percentage").default(0),
  // Discount percentage (0-100)
  category: varchar("category", { length: 50 }).notNull(),
  // 'women', 'men', 'unisex'
  categories: text("categories").array().notNull().default(sql`'{}'`),
  // Multiple categories for filtering
  brand: varchar("brand", { length: 100 }),
  // brand name
  capacity: varchar("capacity", { length: 20 }),
  // product capacity/volume (e.g., 100ML, 75ML)
  imageUrl: text("image_url"),
  inStock: boolean("in_stock").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var cartItems = pgTable("cart_items", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  productId: varchar("product_id").notNull().references(() => products.id, { onDelete: "cascade" }),
  quantity: integer("quantity").notNull().default(1),
  createdAt: timestamp("created_at").defaultNow()
});
var orders = pgTable("orders", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orderCode: varchar("order_code", { length: 20 }).unique().notNull(),
  // Unique readable order code
  userId: varchar("user_id").references(() => users.id),
  status: varchar("status", { length: 50 }).notNull().default("pending"),
  // 'pending', 'confirmed', 'shipped', 'delivered'
  total: decimal("total", { precision: 10, scale: 2 }).notNull(),
  shippingAddress: text("shipping_address").notNull(),
  billingAddress: text("billing_address").notNull(),
  paymentId: varchar("payment_id", { length: 100 }),
  // BOG Payment ID
  paymentStatus: varchar("payment_status", { length: 50 }).default("pending"),
  // pending, approved, completed, failed, cancelled
  paymentMethod: varchar("payment_method", { length: 50 }).default("bog"),
  // bog, card, etc.
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var orderItems = pgTable("order_items", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  orderId: varchar("order_id").notNull().references(() => orders.id, { onDelete: "cascade" }),
  productId: varchar("product_id").notNull().references(() => products.id),
  quantity: integer("quantity").notNull(),
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  createdAt: timestamp("created_at").defaultNow()
});
var newsletters = pgTable("newsletters", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email", { length: 255 }).notNull().unique(),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow()
});
var contactMessages = pgTable("contact_messages", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  firstName: varchar("first_name", { length: 100 }).notNull(),
  lastName: varchar("last_name", { length: 100 }).notNull(),
  email: varchar("email", { length: 255 }).notNull(),
  subject: varchar("subject", { length: 200 }).notNull(),
  message: text("message").notNull(),
  isRead: boolean("is_read").default(false),
  createdAt: timestamp("created_at").defaultNow()
});
var translations = pgTable("translations", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  key: varchar("key", { length: 500 }).notNull().unique(),
  englishText: text("english_text").notNull(),
  georgianText: text("georgian_text").default(""),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow()
});
var usersRelations = relations(users, ({ many }) => ({
  cartItems: many(cartItems),
  orders: many(orders)
}));
var productsRelations = relations(products, ({ many }) => ({
  cartItems: many(cartItems),
  orderItems: many(orderItems)
}));
var cartItemsRelations = relations(cartItems, ({ one }) => ({
  user: one(users, {
    fields: [cartItems.userId],
    references: [users.id]
  }),
  product: one(products, {
    fields: [cartItems.productId],
    references: [products.id]
  })
}));
var ordersRelations = relations(orders, ({ one, many }) => ({
  user: one(users, {
    fields: [orders.userId],
    references: [users.id]
  }),
  orderItems: many(orderItems)
}));
var orderItemsRelations = relations(orderItems, ({ one }) => ({
  order: one(orders, {
    fields: [orderItems.orderId],
    references: [orders.id]
  }),
  product: one(products, {
    fields: [orderItems.productId],
    references: [products.id]
  })
}));
var insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
var registerSchema = createInsertSchema(users).pick({
  email: true,
  password: true,
  firstName: true,
  lastName: true
}).extend({
  confirmPassword: z.string()
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"]
});
var loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required")
});
var insertProductSchema = createInsertSchema(products).omit({
  id: true,
  createdAt: true,
  updatedAt: true
}).extend({
  descriptionGeorgian: z.string().optional(),
  descriptionEnglish: z.string().optional(),
  capacity: z.string().optional()
});
var insertCartItemSchema = createInsertSchema(cartItems).omit({
  id: true,
  createdAt: true
});
var insertOrderSchema = createInsertSchema(orders).omit({
  id: true,
  orderCode: true,
  // Auto-generated, so exclude from manual insertion
  createdAt: true,
  updatedAt: true
});
var insertOrderItemSchema = createInsertSchema(orderItems).omit({
  id: true,
  createdAt: true
});
var insertNewsletterSchema = createInsertSchema(newsletters).omit({
  id: true,
  createdAt: true
});
var insertContactMessageSchema = createInsertSchema(contactMessages).omit({
  id: true,
  createdAt: true
});
var insertTranslationSchema = createInsertSchema(translations).omit({
  id: true,
  createdAt: true,
  updatedAt: true
});

// server/db.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/storage.ts
import { eq, and, desc } from "drizzle-orm";
function generateOrderCode() {
  const timestamp2 = Date.now().toString().slice(-3);
  const random = Math.floor(Math.random() * 999).toString().padStart(3, "0");
  return `${timestamp2}${random}`;
}
var DatabaseStorage = class {
  // User operations
  async getUser(id) {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }
  async getUserByEmail(email) {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }
  async createUser(user) {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }
  async updateUser(id, user) {
    const [updatedUser] = await db.update(users).set({ ...user, updatedAt: /* @__PURE__ */ new Date() }).where(eq(users.id, id)).returning();
    return updatedUser;
  }
  // Product operations
  async getProducts() {
    return await db.select().from(products).orderBy(desc(products.createdAt));
  }
  async getProduct(id) {
    const [product] = await db.select().from(products).where(eq(products.id, id));
    return product;
  }
  async createProduct(product) {
    const [newProduct] = await db.insert(products).values(product).returning();
    return newProduct;
  }
  async updateProduct(id, product) {
    const [updatedProduct] = await db.update(products).set({ ...product, updatedAt: /* @__PURE__ */ new Date() }).where(eq(products.id, id)).returning();
    return updatedProduct;
  }
  async deleteProduct(id) {
    try {
      await db.delete(cartItems).where(eq(cartItems.productId, id));
      await db.delete(orderItems).where(eq(orderItems.productId, id));
      const result = await db.delete(products).where(eq(products.id, id));
      return (result.rowCount || 0) > 0;
    } catch (error) {
      console.error("Error deleting product:", error);
      throw error;
    }
  }
  async getProductById(id) {
    const [product] = await db.select().from(products).where(eq(products.id, id));
    return product;
  }
  async bulkUpdateProductPricing(productIds, discountPercentage) {
    const updatedProducts = [];
    for (const productId of productIds) {
      const [updatedProduct] = await db.update(products).set({
        discountPercentage,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq(products.id, productId)).returning();
      if (updatedProduct) {
        updatedProducts.push(updatedProduct);
      }
    }
    return updatedProducts;
  }
  async resetAllProductDiscounts() {
    const updatedProducts = await db.update(products).set({
      discountPercentage: 0,
      updatedAt: /* @__PURE__ */ new Date()
    }).returning();
    return updatedProducts;
  }
  // Cart operations
  async getCartItems(userId) {
    return await db.select().from(cartItems).leftJoin(products, eq(cartItems.productId, products.id)).where(eq(cartItems.userId, userId)).then(
      (rows) => rows.map((row) => ({
        ...row.cart_items,
        product: row.products
      }))
    );
  }
  async addToCart(cartItem) {
    const [existingItem] = await db.select().from(cartItems).where(and(
      eq(cartItems.userId, cartItem.userId),
      eq(cartItems.productId, cartItem.productId)
    ));
    if (existingItem) {
      const [updatedItem] = await db.update(cartItems).set({ quantity: (existingItem.quantity || 0) + (cartItem.quantity || 1) }).where(eq(cartItems.id, existingItem.id)).returning();
      return updatedItem;
    } else {
      const [newItem] = await db.insert(cartItems).values(cartItem).returning();
      return newItem;
    }
  }
  async updateCartItem(id, quantity) {
    const [updatedItem] = await db.update(cartItems).set({ quantity }).where(eq(cartItems.id, id)).returning();
    return updatedItem;
  }
  async removeFromCart(id) {
    await db.delete(cartItems).where(eq(cartItems.id, id));
  }
  async clearCart(userId) {
    await db.delete(cartItems).where(eq(cartItems.userId, userId));
  }
  // Order operations
  async createOrder(order, orderItemsData) {
    let orderCode = generateOrderCode();
    let attempts = 0;
    while (attempts < 10) {
      const [existingOrder] = await db.select().from(orders).where(eq(orders.orderCode, orderCode));
      if (!existingOrder) break;
      orderCode = generateOrderCode();
      attempts++;
    }
    const orderWithCode = {
      ...order,
      orderCode
    };
    const [newOrder] = await db.insert(orders).values(orderWithCode).returning();
    const orderItemsWithOrderId = orderItemsData.map((item) => ({
      ...item,
      orderId: newOrder.id
    }));
    await db.insert(orderItems).values(orderItemsWithOrderId);
    return newOrder;
  }
  async getOrders(userId) {
    const userOrders = await db.select().from(orders).where(and(
      eq(orders.userId, userId),
      eq(orders.paymentStatus, "completed")
    )).orderBy(desc(orders.createdAt));
    const result = [];
    for (const order of userOrders) {
      const items = await db.select().from(orderItems).leftJoin(products, eq(orderItems.productId, products.id)).where(eq(orderItems.orderId, order.id));
      result.push({
        ...order,
        orderItems: items.map((item) => ({
          ...item.order_items,
          product: item.products
        }))
      });
    }
    return result;
  }
  async getAllOrders() {
    const allOrders = await db.select().from(orders).leftJoin(users, eq(orders.userId, users.id)).orderBy(desc(orders.createdAt));
    const result = [];
    for (const orderRow of allOrders) {
      const items = await db.select().from(orderItems).leftJoin(products, eq(orderItems.productId, products.id)).where(eq(orderItems.orderId, orderRow.orders.id));
      result.push({
        ...orderRow.orders,
        user: orderRow.users,
        orderItems: items.map((item) => ({
          ...item.order_items,
          product: item.products
        }))
      });
    }
    return result;
  }
  async getOrder(orderId) {
    const [order] = await db.select().from(orders).where(eq(orders.id, orderId));
    return order;
  }
  async getOrderByCode(orderCode) {
    const [order] = await db.select().from(orders).where(and(
      eq(orders.orderCode, orderCode),
      eq(orders.paymentStatus, "completed")
    ));
    if (!order) return null;
    const items = await db.select().from(orderItems).leftJoin(products, eq(orderItems.productId, products.id)).where(eq(orderItems.orderId, order.id));
    return {
      ...order,
      orderItems: items.map((item) => ({
        ...item.order_items,
        product: item.products
      }))
    };
  }
  async updateOrderStatus(orderId, status, paymentStatus) {
    const updateData = { status, updatedAt: /* @__PURE__ */ new Date() };
    if (paymentStatus) {
      updateData.paymentStatus = paymentStatus;
    }
    const [updatedOrder] = await db.update(orders).set(updateData).where(eq(orders.id, orderId)).returning();
    return updatedOrder;
  }
  async deleteOrder(orderId) {
    try {
      await db.delete(orderItems).where(eq(orderItems.orderId, orderId));
      const result = await db.delete(orders).where(eq(orders.id, orderId));
      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      console.error("Error deleting order:", error);
      return false;
    }
  }
  async updateOrderPayment(orderId, paymentId, paymentStatus) {
    const [updatedOrder] = await db.update(orders).set({
      paymentId,
      paymentStatus,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq(orders.id, orderId)).returning();
    return updatedOrder;
  }
  // Newsletter operations
  async subscribeNewsletter(newsletter) {
    try {
      const [newSubscription] = await db.insert(newsletters).values(newsletter).returning();
      return newSubscription;
    } catch (error) {
      const [existing] = await db.update(newsletters).set({ isActive: true }).where(eq(newsletters.email, newsletter.email)).returning();
      return existing;
    }
  }
  async unsubscribeNewsletter(email) {
    await db.update(newsletters).set({ isActive: false }).where(eq(newsletters.email, email));
  }
  // Contact operations
  async createContactMessage(message) {
    const [newMessage] = await db.insert(contactMessages).values(message).returning();
    return newMessage;
  }
  async getContactMessages() {
    return await db.select().from(contactMessages).orderBy(desc(contactMessages.createdAt));
  }
  async markMessageAsRead(id) {
    const [updatedMessage] = await db.update(contactMessages).set({ isRead: true }).where(eq(contactMessages.id, id)).returning();
    return updatedMessage;
  }
  // Translation operations
  async getAllTranslations() {
    return await db.select().from(translations).orderBy(translations.key);
  }
  async getTranslation(key) {
    const [translation] = await db.select().from(translations).where(eq(translations.key, key));
    return translation;
  }
  async createTranslation(translation) {
    const [newTranslation] = await db.insert(translations).values(translation).returning();
    return newTranslation;
  }
  async updateTranslation(key, georgianText) {
    const [updatedTranslation] = await db.update(translations).set({
      georgianText,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq(translations.key, key)).returning();
    return updatedTranslation;
  }
  async bulkCreateTranslations(translationList) {
    const results = [];
    for (const translation of translationList) {
      try {
        const [newTranslation] = await db.insert(translations).values(translation).returning();
        results.push(newTranslation);
      } catch (error) {
        const [updatedTranslation] = await db.update(translations).set({
          englishText: translation.englishText,
          updatedAt: /* @__PURE__ */ new Date()
        }).where(eq(translations.key, translation.key)).returning();
        if (updatedTranslation) {
          results.push(updatedTranslation);
        }
      }
    }
    return results;
  }
};
var storage = new DatabaseStorage();

// server/auth.ts
import session from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import connectPg from "connect-pg-simple";
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
function setupAuth(app) {
  const PostgresSessionStore = connectPg(session);
  const sessionStore = new PostgresSessionStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: true,
    ttl: 7 * 24 * 60 * 60
    // 1 week
  });
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "your-secret-key-change-in-production",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1e3
      // 1 week
    }
  };
  app.set("trust proxy", 1);
  app.use(session(sessionSettings));
  app.post("/api/register", async (req, res) => {
    try {
      const validatedData = registerSchema.parse(req.body);
      const existingUser = await storage.getUserByEmail(validatedData.email);
      if (existingUser) {
        return res.status(400).json({ message: "User already exists with this email" });
      }
      const hashedPassword = await hashPassword(validatedData.password);
      const user = await storage.createUser({
        email: validatedData.email,
        password: hashedPassword,
        firstName: validatedData.firstName,
        lastName: validatedData.lastName
      });
      req.session.userId = user.id;
      const { password, ...userWithoutPassword } = user;
      res.status(201).json(userWithoutPassword);
    } catch (error) {
      console.error("Registration error:", error);
      if (error.name === "ZodError") {
        return res.status(400).json({
          message: "Validation error",
          errors: error.errors
        });
      }
      res.status(500).json({ message: "Registration failed" });
    }
  });
  app.post("/api/login", async (req, res) => {
    try {
      const validatedData = loginSchema.parse(req.body);
      const user = await storage.getUserByEmail(validatedData.email);
      if (!user || !await comparePasswords(validatedData.password, user.password)) {
        return res.status(401).json({ message: "Invalid email or password" });
      }
      req.session.userId = user.id;
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (error) {
      console.error("Login error:", error);
      if (error.name === "ZodError") {
        return res.status(400).json({
          message: "Validation error",
          errors: error.errors
        });
      }
      res.status(500).json({ message: "Login failed" });
    }
  });
  app.post("/api/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error("Logout error:", err);
        return res.status(500).json({ message: "Logout failed" });
      }
      res.clearCookie("connect.sid");
      res.json({ message: "Logged out successfully" });
    });
  });
  app.get("/api/user", async (req, res) => {
    try {
      const userId = req.session?.userId;
      if (!userId) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(401).json({ message: "User not found" });
      }
      const { password, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (error) {
      console.error("Get user error:", error);
      res.status(500).json({ message: "Failed to get user" });
    }
  });
  app.put("/api/user/profile", async (req, res) => {
    try {
      const userId = req.session?.userId;
      if (!userId) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      const { firstName, lastName, email } = req.body;
      if (!firstName || !lastName || !email) {
        return res.status(400).json({ message: "First name, last name, and email are required" });
      }
      if (email) {
        const existingUser = await storage.getUserByEmail(email);
        if (existingUser && existingUser.id !== userId) {
          return res.status(400).json({ message: "Email is already taken by another user" });
        }
      }
      const updatedUser = await storage.updateUser(userId, {
        firstName,
        lastName,
        email
      });
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      const { password, ...userWithoutPassword } = updatedUser;
      res.json(userWithoutPassword);
    } catch (error) {
      console.error("Update profile error:", error);
      res.status(500).json({ message: "Failed to update profile" });
    }
  });
  app.post("/api/admin/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (username.toLowerCase() === "giorgi" && password.toLowerCase() === "random12") {
        req.session.isAdminAuthenticated = true;
        res.json({ success: true, message: "Admin authenticated successfully" });
      } else {
        res.status(401).json({ message: "Invalid admin credentials" });
      }
    } catch (error) {
      console.error("Admin login error:", error);
      res.status(500).json({ message: "Failed to authenticate admin" });
    }
  });
  app.post("/api/admin/logout", (req, res) => {
    req.session.isAdminAuthenticated = false;
    res.json({ success: true, message: "Admin logged out successfully" });
  });
  app.get("/api/admin/auth", (req, res) => {
    const isAdminAuthenticated = req.session?.isAdminAuthenticated || false;
    res.json({ isAuthenticated: isAdminAuthenticated });
  });
}
function requireAuth(req, res, next) {
  const userId = req.session?.userId;
  if (!userId) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
}
function requireAdmin(req, res, next) {
  const isAdminAuthenticated = req.session?.isAdminAuthenticated;
  if (!isAdminAuthenticated) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
}

// server/bogPayment.ts
var BOGPaymentService = class {
  // Correct BOG Payment API endpoints based on official documentation
  authUrl = "https://oauth2.bog.ge/auth/realms/bog/protocol/openid-connect/token";
  apiBaseUrl = "https://api.bog.ge/payments/v1";
  clientId;
  clientSecret;
  accessToken;
  tokenExpiry;
  constructor() {
    this.clientId = process.env.BOG_CLIENT_ID || "";
    this.clientSecret = process.env.BOG_CLIENT_SECRET || "";
    if (!this.clientId || !this.clientSecret) {
      console.warn(
        "BOG credentials missing. Set BOG_CLIENT_ID and BOG_CLIENT_SECRET in environment variables."
      );
    } else {
      console.log("BOG credentials detected. Client ID configured.");
    }
  }
  async getAccessToken() {
    if (this.accessToken && this.tokenExpiry && Date.now() < this.tokenExpiry) {
      return this.accessToken;
    }
    try {
      const credentials = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      const response = await fetch(this.authUrl, {
        method: "POST",
        headers: {
          "Authorization": `Basic ${credentials}`,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: "grant_type=client_credentials"
      });
      if (!response.ok) {
        const errorText = await response.text();
        console.error("BOG API Response:", errorText);
        throw new Error(`BOG token request failed: ${response.status} - ${errorText}`);
      }
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        const responseText = await response.text();
        console.error("Non-JSON response from BOG API:", responseText);
        throw new Error("BOG API returned non-JSON response");
      }
      const tokenData = await response.json();
      this.accessToken = tokenData.access_token;
      this.tokenExpiry = Date.now() + tokenData.expires_in * 1e3 - 6e4;
      return this.accessToken;
    } catch (error) {
      console.error("Error getting BOG access token:", error);
      throw error;
    }
  }
  async createOrder(orderRequest) {
    try {
      const token = await this.getAccessToken();
      const response = await fetch(`${this.apiBaseUrl}/ecommerce/orders`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
          "Accept-Language": "en"
          // English interface
        },
        body: JSON.stringify(orderRequest)
      });
      if (!response.ok) {
        const errorText = await response.text();
        console.error("BOG Order Creation Error:", errorText);
        throw new Error(`BOG order creation failed: ${response.status} - ${errorText}`);
      }
      const orderData = await response.json();
      return orderData;
    } catch (error) {
      console.error("Error creating BOG order:", error);
      throw error;
    }
  }
  async getOrderDetails(orderId) {
    try {
      const token = await this.getAccessToken();
      const response = await fetch(`${this.apiBaseUrl}/receipt/${orderId}`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        }
      });
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`BOG order details retrieval failed: ${response.status} - ${errorText}`);
      }
      const orderData = await response.json();
      return orderData;
    } catch (error) {
      console.error("Error retrieving BOG order details:", error);
      throw error;
    }
  }
  getPaymentUrl(orderResponse) {
    return orderResponse._links.redirect.href;
  }
  getDetailsUrl(orderResponse) {
    return orderResponse._links.details.href;
  }
};
var bogPaymentService = new BOGPaymentService();

// server/email.ts
import nodemailer from "nodemailer";
var createTransporter = () => {
  const emailProvider = process.env.EMAIL_PROVIDER || "gmail";
  if (emailProvider === "outlook" || emailProvider === "hotmail") {
    return nodemailer.createTransport({
      host: "smtp-mail.outlook.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        // Your Outlook/Hotmail address
        pass: process.env.EMAIL_PASSWORD
        // Your regular password
      }
    });
  } else {
    return nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        // Your Gmail address
        pass: process.env.EMAIL_APP_PASSWORD
        // Gmail App Password (not regular password)
      }
    });
  }
};
async function sendOrderNotificationEmail(orderData) {
  try {
    console.log("sendOrderNotificationEmail called for order:", orderData.orderId);
    const emailProvider = process.env.EMAIL_PROVIDER || "gmail";
    const passwordField = emailProvider === "outlook" || emailProvider === "hotmail" ? "EMAIL_PASSWORD" : "EMAIL_APP_PASSWORD";
    const requiredPassword = emailProvider === "outlook" || emailProvider === "hotmail" ? process.env.EMAIL_PASSWORD : process.env.EMAIL_APP_PASSWORD;
    if (!process.env.EMAIL_USER || !requiredPassword) {
      console.log(`Email credentials not configured for ${emailProvider}, skipping email notification`);
      return true;
    }
    console.log("Email credentials verified, proceeding with sending...");
    const transporter = createTransporter();
    const itemsList = orderData.items.map((item) => `\u2022 ${item.productName} x${item.quantity} - \u20BE${item.price.toFixed(2)}`).join("\n");
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
      // Send to admin email or fallback to sender
      subject: `New Order #${orderData.orderId} - Vel France`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1a365d;">New Order Received!</h2>
          
          <div style="background-color: #f7fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #2d3748;">Order Details</h3>
            <p><strong>Order ID:</strong> ${orderData.orderId}</p>
            <p><strong>Customer:</strong> ${orderData.customerName}</p>
            <p><strong>Email:</strong> ${orderData.customerEmail}</p>
            <p><strong>Total Amount:</strong> \u20BE${orderData.totalAmount.toFixed(2)}</p>
            <p><strong>Payment Method:</strong> ${orderData.paymentMethod}</p>
          </div>

          <div style="background-color: #f7fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #2d3748;">Items Ordered</h3>
            <pre style="font-family: Arial, sans-serif; white-space: pre-wrap;">${itemsList}</pre>
          </div>

          <div style="background-color: #f7fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #2d3748;">Shipping Address</h3>
            <p style="white-space: pre-wrap;">${orderData.shippingAddress}</p>
          </div>

          <div style="margin-top: 30px; padding: 20px; background-color: #edf2f7; border-radius: 10px;">
            <p style="margin: 0; color: #4a5568;">
              This order was placed on Vel France perfume store. Please process this order promptly.
            </p>
          </div>
        </div>
      `
    };
    await transporter.sendMail(mailOptions);
    console.log(`Order notification email sent for order ${orderData.orderId}`);
    return true;
  } catch (error) {
    console.error("Failed to send order notification email:", error);
    return false;
  }
}
async function sendOrderConfirmationToCustomer(orderData) {
  try {
    console.log("sendOrderConfirmationToCustomer called for order:", orderData.orderId);
    const emailProvider = process.env.EMAIL_PROVIDER || "gmail";
    const requiredPassword = emailProvider === "outlook" || emailProvider === "hotmail" ? process.env.EMAIL_PASSWORD : process.env.EMAIL_APP_PASSWORD;
    if (!process.env.EMAIL_USER || !requiredPassword) {
      console.log(`Email credentials not configured for ${emailProvider}, skipping customer confirmation email`);
      return true;
    }
    console.log("Customer email credentials verified, proceeding with sending...");
    const transporter = createTransporter();
    const itemsList = orderData.items.map((item) => `\u2022 ${item.productName} x${item.quantity} - \u20BE${item.price.toFixed(2)}`).join("\n");
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: orderData.customerEmail,
      subject: `Order Confirmation #${orderData.orderId} - Vel France`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1a365d;">Thank you for your order!</h2>
          
          <p>Dear ${orderData.customerName},</p>
          <p>We've received your order and are preparing it for shipment. Here are your order details:</p>

          <div style="background-color: #f7fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #2d3748;">Order #${orderData.orderId}</h3>
            <p><strong>Total Amount:</strong> \u20BE${orderData.totalAmount.toFixed(2)}</p>
            <p><strong>Payment Method:</strong> ${orderData.paymentMethod}</p>
          </div>

          <div style="background-color: #f7fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #2d3748;">Items Ordered</h3>
            <pre style="font-family: Arial, sans-serif; white-space: pre-wrap;">${itemsList}</pre>
          </div>

          <div style="background-color: #f7fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3 style="color: #2d3748;">Shipping Address</h3>
            <p style="white-space: pre-wrap;">${orderData.shippingAddress}</p>
          </div>

          <div style="margin-top: 30px; padding: 20px; background-color: #edf2f7; border-radius: 10px;">
            <p style="margin: 0; color: #4a5568;">
              <strong>Delivery Information:</strong><br>
              \u2022 Tbilisi: 1-2 business days<br>
              \u2022 Regions: 2-3 business days
            </p>
          </div>

          <p style="margin-top: 20px;">
            Thank you for choosing Vel France!<br>
            <strong>I/E PERFUMETRADE NETWORK</strong><br>
            Tbilisi, Vaja Pshavela 70g
          </p>
        </div>
      `
    };
    await transporter.sendMail(mailOptions);
    console.log(`Order confirmation email sent to customer for order ${orderData.orderId}`);
    return true;
  } catch (error) {
    console.error("Failed to send customer confirmation email:", error);
    return false;
  }
}

// server/routes.ts
function buildLanguageAwareURL(baseUrl, path, language) {
  if (language === "en") {
    return `${baseUrl}/en${path}`;
  }
  return `${baseUrl}${path}`;
}
function getBOGPaymentConfig(paymentMethod, totalAmount) {
  switch (paymentMethod) {
    case "card":
      return {
        payment_method: ["card", "google_pay", "apple_pay", "bog_p2p", "bog_loyalty"]
      };
    case "installment":
      return {
        payment_method: ["bnpl"],
        // Use bnpl payment method
        bnpl: false,
        // Show only standard installment plan
        config: {
          loan: {
            type: void 0,
            // Discount code from BOG calculator (undefined for no discount)
            month: 12
            // 12-month installment plan
          }
        }
      };
    case "bnpl":
      return {
        payment_method: ["bnpl"],
        // Use bnpl payment method
        bnpl: true,
        // Show only payment in installments (part-by-part)
        config: {
          loan: {
            type: void 0,
            // Discount code from BOG calculator (undefined for no discount)
            month: 6
            // 6-month part-by-part plan
          }
        }
      };
    default:
      return { payment_method: ["card"] };
  }
}
async function registerRoutes(app) {
  setupAuth(app);
  app.get("/api/products", async (req, res) => {
    try {
      const products2 = await storage.getProducts();
      res.json(products2);
    } catch (error) {
      console.error("Error fetching products:", error);
      res.status(500).json({ message: "Failed to fetch products" });
    }
  });
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
  app.get("/api/admin/products", requireAdmin, async (req, res) => {
    try {
      const products2 = await storage.getProducts();
      res.json(products2);
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
      res.status(400).json({ message: "Failed to create product", error: error.message });
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
      res.status(400).json({ message: "Failed to update product", error: error.message });
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
  app.post("/api/admin/products/bulk-pricing", requireAdmin, async (req, res) => {
    try {
      const { productIds, discountPercentage } = req.body;
      if (!Array.isArray(productIds) || productIds.length === 0) {
        return res.status(400).json({ message: "Product IDs array is required" });
      }
      if (typeof discountPercentage !== "number" || discountPercentage < 0 || discountPercentage > 100) {
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
  app.get("/api/cart", async (req, res) => {
    try {
      if (!req.session.userId) {
        const sessionCart = req.session.cart || [];
        const cartWithProducts = [];
        for (const item of sessionCart) {
          const product = await storage.getProduct(item.productId);
          if (product) {
            cartWithProducts.push({
              id: item.id,
              userId: null,
              productId: item.productId,
              quantity: item.quantity,
              createdAt: /* @__PURE__ */ new Date(),
              product
            });
          }
        }
        return res.json(cartWithProducts);
      }
      const userId = req.session.userId;
      const cartItems2 = await storage.getCartItems(userId);
      res.json(cartItems2);
    } catch (error) {
      console.error("Error fetching cart:", error);
      res.status(500).json({ message: "Failed to fetch cart" });
    }
  });
  app.post("/api/cart", async (req, res) => {
    try {
      const { productId, quantity = 1 } = req.body;
      if (!req.session.userId) {
        if (!req.session.cart) {
          req.session.cart = [];
        }
        const sessionCart = req.session.cart;
        const existingItem = sessionCart.find((item) => item.productId === productId);
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
        const cartItem2 = {
          id: existingItem?.id || sessionCart[sessionCart.length - 1].id,
          userId: null,
          productId,
          quantity: existingItem ? existingItem.quantity : quantity,
          createdAt: /* @__PURE__ */ new Date(),
          product
        };
        return res.json(cartItem2);
      }
      const userId = req.session.userId;
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
  app.put("/api/cart/:id", async (req, res) => {
    try {
      const { quantity } = req.body;
      const itemId = req.params.id;
      if (!req.session.userId) {
        const sessionCart = req.session.cart || [];
        const item = sessionCart.find((item2) => item2.id === itemId);
        if (item) {
          item.quantity = quantity;
          const product = await storage.getProduct(item.productId);
          return res.json({
            id: item.id,
            userId: null,
            productId: item.productId,
            quantity: item.quantity,
            createdAt: /* @__PURE__ */ new Date(),
            product
          });
        }
        return res.status(404).json({ message: "Item not found" });
      }
      const cartItem = await storage.updateCartItem(itemId, quantity);
      res.json(cartItem);
    } catch (error) {
      console.error("Error updating cart item:", error);
      res.status(500).json({ message: "Failed to update cart item" });
    }
  });
  app.delete("/api/cart/:id", async (req, res) => {
    try {
      const itemId = req.params.id;
      if (!req.session.userId) {
        const sessionCart = req.session.cart || [];
        const index2 = sessionCart.findIndex((item) => item.id === itemId);
        if (index2 > -1) {
          sessionCart.splice(index2, 1);
        }
        return res.json({ message: "Item removed from cart" });
      }
      await storage.removeFromCart(itemId);
      res.json({ message: "Item removed from cart" });
    } catch (error) {
      console.error("Error removing from cart:", error);
      res.status(500).json({ message: "Failed to remove from cart" });
    }
  });
  app.delete("/api/cart", async (req, res) => {
    try {
      if (!req.session.userId) {
        req.session.cart = [];
        return res.json({ message: "Cart cleared" });
      }
      const userId = req.session.userId;
      await storage.clearCart(userId);
      res.json({ message: "Cart cleared" });
    } catch (error) {
      console.error("Error clearing cart:", error);
      res.status(500).json({ message: "Failed to clear cart" });
    }
  });
  app.post("/api/payments/initiate-with-calculator", async (req, res) => {
    try {
      const userId = req.session.userId || null;
      const { shippingAddress, billingAddress, items, calculatorResult, paymentMethod, language } = req.body;
      let total = 0;
      const orderItems2 = [];
      for (const item of items) {
        const product = await storage.getProduct(item.productId);
        if (!product) {
          return res.status(400).json({ message: `Product ${item.productId} not found` });
        }
        const basePrice = parseFloat(product.price);
        const discountedPrice = product.discountPercentage && product.discountPercentage > 0 ? basePrice * (1 - product.discountPercentage / 100) : basePrice;
        const itemTotal = discountedPrice * item.quantity;
        total += itemTotal;
        orderItems2.push({
          productId: item.productId,
          quantity: item.quantity,
          price: discountedPrice.toString()
        });
      }
      const orderData = insertOrderSchema.parse({
        userId,
        total: total.toString(),
        shippingAddress,
        billingAddress,
        paymentStatus: "pending"
      });
      const order = await storage.createOrder(orderData, orderItems2);
      const baseUrl = `${req.protocol}://${req.get("host")}`;
      let paymentConfig = {};
      if (paymentMethod === "bnpl") {
        paymentConfig = {
          payment_method: ["bnpl"],
          bnpl: true,
          config: {
            loan: {
              type: calculatorResult.discount_code || "zero",
              month: calculatorResult.month || 6
            }
          }
        };
      } else {
        paymentConfig = {
          payment_method: ["bog_loan"],
          // Use bog_loan for standard installments
          config: {
            loan: {
              type: calculatorResult.discount_code || "standard",
              month: calculatorResult.month || 12
            }
          }
        };
      }
      console.log(`Using BOG Calculator: ${calculatorResult.month} months (${paymentMethod}), payment_method: ${paymentMethod === "bnpl" ? "bnpl" : "bog_loan"}`);
      const bogOrderRequest = {
        callback_url: `${baseUrl}/api/payments/callback`,
        external_order_id: order.id,
        purchase_units: {
          currency: "GEL",
          total_amount: parseFloat(total.toFixed(2)),
          // Keep as lari with decimal precision
          basket: orderItems2.map((item) => ({
            product_id: item.productId,
            description: `Product ${item.productId}`,
            quantity: item.quantity,
            unit_price: parseFloat(parseFloat(item.price).toFixed(2)),
            // Keep as lari with decimal precision
            total_price: parseFloat((item.quantity * parseFloat(item.price)).toFixed(2))
            // Keep as lari with decimal precision
          }))
        },
        redirect_urls: {
          success: buildLanguageAwareURL(baseUrl, `/payment-success?orderCode=${order.orderCode}`, language),
          fail: buildLanguageAwareURL(baseUrl, `/payment-cancel`, language)
        },
        ttl: 60,
        ...paymentConfig,
        capture: "automatic",
        application_type: "web"
      };
      console.log(`Creating BOG order with calculator result:`, calculatorResult);
      console.log("BOG Order Request:", JSON.stringify(bogOrderRequest, null, 2));
      const bogOrder = await bogPaymentService.createOrder(bogOrderRequest);
      console.log("BOG Order Response:", JSON.stringify(bogOrder, null, 2));
      await storage.updateOrderPayment(order.id, bogOrder.id, "pending");
      const paymentUrl = bogPaymentService.getPaymentUrl(bogOrder);
      const response = {
        orderId: order.id,
        paymentId: bogOrder.id,
        paymentUrl,
        status: "created"
      };
      res.json(response);
    } catch (error) {
      console.error("Error initiating calculator payment:", error);
      res.status(500).json({ message: "Failed to initiate payment" });
    }
  });
  app.post("/api/payments/initiate", async (req, res) => {
    try {
      const userId = req.session.userId || null;
      const { shippingAddress, billingAddress, items, paymentMethod = "card", language } = req.body;
      let total = 0;
      const orderItems2 = [];
      for (const item of items) {
        const product = await storage.getProduct(item.productId);
        if (!product) {
          return res.status(400).json({ message: `Product ${item.productId} not found` });
        }
        const basePrice = parseFloat(product.price);
        const discountedPrice = product.discountPercentage && product.discountPercentage > 0 ? basePrice * (1 - product.discountPercentage / 100) : basePrice;
        const itemTotal = discountedPrice * item.quantity;
        total += itemTotal;
        orderItems2.push({
          productId: item.productId,
          quantity: item.quantity,
          price: discountedPrice.toString()
        });
      }
      const orderData = insertOrderSchema.parse({
        userId,
        total: total.toString(),
        shippingAddress,
        billingAddress,
        paymentStatus: "pending"
      });
      const order = await storage.createOrder(orderData, orderItems2);
      const baseUrl = `${req.protocol}://${req.get("host")}`;
      const paymentConfig = getBOGPaymentConfig(paymentMethod, total);
      const bogOrderRequest = {
        callback_url: `${baseUrl}/api/payments/callback`,
        external_order_id: order.id,
        purchase_units: {
          currency: "GEL",
          total_amount: parseFloat(total.toFixed(2)),
          // Keep as lari with decimal precision
          basket: orderItems2.map((item) => ({
            product_id: item.productId,
            description: `Product ${item.productId}`,
            // You might want to get actual product name
            quantity: item.quantity,
            unit_price: parseFloat(parseFloat(item.price).toFixed(2)),
            // Keep as lari with decimal precision
            total_price: parseFloat((item.quantity * parseFloat(item.price)).toFixed(2))
            // Keep as lari with decimal precision
          }))
        },
        redirect_urls: {
          success: buildLanguageAwareURL(baseUrl, `/payment-success?orderCode=${order.orderCode}`, language),
          fail: buildLanguageAwareURL(baseUrl, `/payment-cancel`, language)
        },
        ttl: 60,
        // 60 minutes to complete payment
        ...paymentConfig,
        // Set payment method and bnpl config
        capture: "automatic",
        // Immediate capture
        application_type: "web"
      };
      console.log(`Creating BOG order for payment method: ${paymentMethod}`);
      console.log("BOG Order Request:", JSON.stringify(bogOrderRequest, null, 2));
      const bogOrder = await bogPaymentService.createOrder(bogOrderRequest);
      console.log("BOG Order Response:", JSON.stringify(bogOrder, null, 2));
      await storage.updateOrderPayment(order.id, bogOrder.id, "pending");
      const paymentUrl = bogPaymentService.getPaymentUrl(bogOrder);
      console.log("Generated Payment URL:", paymentUrl);
      const response = {
        orderId: order.id,
        paymentId: bogOrder.id,
        paymentUrl,
        status: "created"
      };
      console.log("Sending response to frontend:", JSON.stringify(response, null, 2));
      res.json(response);
    } catch (error) {
      console.error("Error initiating payment:", error);
      res.status(500).json({ message: "Failed to initiate payment" });
    }
  });
  app.post("/api/payments/callback", async (req, res) => {
    try {
      console.log("BOG Payment callback received:", req.body);
      const { body } = req.body;
      if (body && body.external_order_id && body.order_status) {
        const externalOrderId = body.external_order_id;
        const bogOrderId = body.order_id;
        const orderStatus = body.order_status.key;
        const mappedOrderStatus = orderStatus === "completed" ? "confirmed" : orderStatus === "failed" ? "cancelled" : "pending";
        const mappedPaymentStatus = orderStatus === "completed" ? "completed" : orderStatus === "failed" ? "failed" : "pending";
        console.log(`Updating order ${externalOrderId} with status: ${mappedOrderStatus}, payment: ${mappedPaymentStatus}`);
        await storage.updateOrderPayment(externalOrderId, bogOrderId, mappedPaymentStatus);
        await storage.updateOrderStatus(externalOrderId, mappedOrderStatus, mappedPaymentStatus);
        if (orderStatus === "completed") {
          const order = await storage.getOrder(externalOrderId);
          if (order) {
            if (order.userId) {
              await storage.clearCart(order.userId);
            }
            try {
              const orderWithItems = await storage.getOrderByCode(order.orderCode);
              if (orderWithItems?.orderItems) {
                let customerName = "Guest Customer";
                let customerEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER || "admin@velfrance.ge";
                if (order.userId) {
                  const user = await storage.getUser(order.userId);
                  if (user) {
                    customerName = user.firstName || user.lastName ? `${user.firstName || ""} ${user.lastName || ""}`.trim() : user.email;
                    customerEmail = user.email;
                  }
                }
                const emailData = {
                  orderId: order.orderCode,
                  customerName,
                  customerEmail,
                  totalAmount: parseFloat(order.total),
                  items: orderWithItems.orderItems.map((item) => ({
                    productName: item.product?.name || `Product ${item.productId}`,
                    quantity: item.quantity,
                    price: parseFloat(item.price)
                  })),
                  shippingAddress: order.shippingAddress,
                  paymentMethod: "BOG Payment Gateway"
                };
                console.log("Sending order notification emails for order:", order.orderCode, "(User ID:", order.userId || "Guest", ")");
                const adminEmailResult = await sendOrderNotificationEmail(emailData);
                console.log("Admin email sent:", adminEmailResult);
                if (order.userId && customerEmail !== (process.env.ADMIN_EMAIL || process.env.EMAIL_USER)) {
                  const customerEmailResult = await sendOrderConfirmationToCustomer(emailData);
                  console.log("Customer email sent:", customerEmailResult);
                } else {
                  console.log("Guest order - customer confirmation email skipped");
                }
              }
            } catch (emailError) {
              console.error("Failed to send order emails:", emailError);
            }
          }
        }
      }
      res.status(200).json({ received: true });
    } catch (error) {
      console.error("Error processing BOG callback:", error);
      res.status(200).json({ received: true });
    }
  });
  app.get("/api/payments/success", async (req, res) => {
    try {
      const { orderId, paymentId } = req.query;
      if (!orderId || !paymentId) {
        return res.status(400).json({ message: "Missing orderId or paymentId" });
      }
      console.log("Payment success callback received for:", orderId, paymentId);
      let orderStatus = "confirmed";
      let paymentStatus = "completed";
      const order = await storage.getOrder(orderId);
      if (order) {
        if (order.userId) {
          await storage.clearCart(order.userId);
        }
        try {
          const orderWithItems = await storage.getOrderByCode(order.orderCode);
          if (orderWithItems?.orderItems) {
            let customerName = "Guest Customer";
            let customerEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER || "admin@velfrance.ge";
            if (order.userId) {
              const user = await storage.getUser(order.userId);
              if (user) {
                customerName = user.firstName || user.lastName ? `${user.firstName || ""} ${user.lastName || ""}`.trim() : user.email;
                customerEmail = user.email;
              }
            }
            const emailData = {
              orderId: order.orderCode,
              customerName,
              customerEmail,
              totalAmount: parseFloat(order.total),
              items: orderWithItems.orderItems.map((item) => ({
                productName: item.product?.name || `Product ${item.productId}`,
                quantity: item.quantity,
                price: parseFloat(item.price)
              })),
              shippingAddress: order.shippingAddress,
              paymentMethod: "BOG Payment Gateway"
            };
            console.log("Sending order notification emails for order:", order.orderCode, "(User ID:", order.userId || "Guest", ")");
            const adminEmailResult = await sendOrderNotificationEmail(emailData);
            console.log("Admin email sent:", adminEmailResult);
            if (order.userId && customerEmail !== (process.env.ADMIN_EMAIL || process.env.EMAIL_USER)) {
              const customerEmailResult = await sendOrderConfirmationToCustomer(emailData);
              console.log("Customer email sent:", customerEmailResult);
            } else {
              console.log("Guest order - customer confirmation email skipped");
            }
          }
        } catch (emailError) {
          console.error("Failed to send order emails:", emailError);
        }
      }
      await storage.updateOrderStatus(orderId, orderStatus, paymentStatus);
      const updatedOrder = await storage.getOrder(orderId);
      res.redirect(`/order/${updatedOrder?.orderCode || orderId}`);
    } catch (error) {
      console.error("Error handling payment success:", error);
      res.redirect(`/?payment=error`);
    }
  });
  app.get("/api/payments/cancel", async (req, res) => {
    try {
      const { orderId } = req.query;
      if (orderId) {
        await storage.updateOrderStatus(orderId, "cancelled", "cancelled");
      }
      res.redirect(`/?payment=cancelled&orderId=${orderId}`);
    } catch (error) {
      console.error("Error handling payment cancellation:", error);
      res.redirect(`/?payment=error`);
    }
  });
  app.post("/api/orders", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      const { shippingAddress, billingAddress, items } = req.body;
      let total = 0;
      const orderItems2 = [];
      for (const item of items) {
        const product = await storage.getProduct(item.productId);
        if (!product) {
          return res.status(400).json({ message: `Product ${item.productId} not found` });
        }
        const itemTotal = parseFloat(product.price) * item.quantity;
        total += itemTotal;
        orderItems2.push({
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
      const order = await storage.createOrder(orderData, orderItems2);
      await storage.clearCart(userId);
      res.json(order);
    } catch (error) {
      console.error("Error creating order:", error);
      res.status(500).json({ message: "Failed to create order" });
    }
  });
  app.get("/api/orders", requireAuth, async (req, res) => {
    try {
      const userId = req.session.userId;
      const orders2 = await storage.getOrders(userId);
      res.json(orders2);
    } catch (error) {
      console.error("Error fetching orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });
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
  app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
      const orders2 = await storage.getAllOrders();
      res.json(orders2);
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
  app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
      const userId = req.session.userId;
      const user = await storage.getUser(userId);
      if (!user?.isAdmin) {
        return res.status(403).json({ message: "Admin access required" });
      }
      const orders2 = await storage.getAllOrders();
      res.json(orders2);
    } catch (error) {
      console.error("Error fetching all orders:", error);
      res.status(500).json({ message: "Failed to fetch orders" });
    }
  });
  app.put("/api/admin/orders/:id/status", requireAdmin, async (req, res) => {
    try {
      const userId = req.session.userId;
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
  app.get("/api/admin/contacts", requireAdmin, async (req, res) => {
    try {
      const userId = req.session.userId;
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
  app.put("/api/admin/contacts/:id/read", requireAdmin, async (req, res) => {
    try {
      const userId = req.session.userId;
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
  app.get("/api/translations", async (req, res) => {
    try {
      const translations2 = await storage.getAllTranslations();
      res.json(translations2);
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
  app.post("/api/admin/translations/bulk", requireAdmin, async (req, res) => {
    try {
      const { translations: translations2 } = req.body;
      if (!Array.isArray(translations2)) {
        return res.status(400).json({ message: "Translations must be an array" });
      }
      const results = await storage.bulkCreateTranslations(translations2);
      res.json({ message: `Successfully processed ${results.length} translations`, results });
    } catch (error) {
      console.error("Error bulk creating translations:", error);
      res.status(500).json({ message: "Failed to bulk create translations" });
    }
  });
  app.put("/api/admin/translations/:key", requireAdmin, async (req, res) => {
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
  app.post("/api/admin/translations", requireAdmin, async (req, res) => {
    try {
      const translationData = req.body;
      const translation = await storage.createTranslation(translationData);
      res.json(translation);
    } catch (error) {
      console.error("Error creating translation:", error);
      res.status(500).json({ message: "Failed to create translation" });
    }
  });
  const httpServer = createServer(app);
  return httpServer;
}
export {
  registerRoutes
};
