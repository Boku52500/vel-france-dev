import express, { type Express } from "express";
import { registerRoutes } from "../server/routes.js";

let app: Express | null = null;
let initPromise: Promise<void> | null = null;

async function initApp() {
  if (app) return;
  app = express();
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: false, limit: "10mb" }));
  // Register all routes (auth, products, cart, orders, payments, admin, etc.)
  await registerRoutes(app);
}

export default async function handler(req: any, res: any) {
  try {
    if (!app) {
      initPromise = initPromise || initApp();
      await initPromise;
    }
    // Delegate handling to Express
    return (app as any)(req, res);
  } catch (err: any) {
    res.statusCode = 500;
    res.end(`Server error: ${err?.message || "unknown"}`);
  }
}
