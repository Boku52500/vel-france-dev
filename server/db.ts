import { config as dotenvConfig } from 'dotenv';
import path from 'path';
import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "../shared/schema";

neonConfig.webSocketConstructor = ws;

// Load .env for local development if DATABASE_URL is not already set
if (!process.env.DATABASE_URL) {
  dotenvConfig(); // root .env if present
  dotenvConfig({ path: path.resolve(process.cwd(), 'backend', '.env'), override: false });
}

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const db = drizzle({ client: pool, schema });