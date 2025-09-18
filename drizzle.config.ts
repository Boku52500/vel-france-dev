import { defineConfig } from "drizzle-kit";
import { config as dotenvConfig } from "dotenv";
import path from "path";

// Load environment variables
dotenvConfig(); // root .env if present
dotenvConfig({ path: path.resolve(process.cwd(), "backend", ".env"), override: false });

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is not set. Add it to backend/.env or export it in your shell.");
}

export default defineConfig({
  out: "./migrations",
  schema: "./shared/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
});
