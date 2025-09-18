import { pool } from "../server/db";

async function main() {
  try {
    const dbInfo = await pool.query<{ db: string; user: string }>(
      "SELECT current_database() AS db, current_user AS user;"
    );
    const count = await pool.query<{ products_count: string }>(
      "SELECT COUNT(*) AS products_count FROM products;"
    );
    const sample = await pool.query(
      `SELECT id, name, price, category, created_at
       FROM products
       ORDER BY created_at DESC
       LIMIT 5;`
    );

    console.log("DB:", dbInfo.rows[0]?.db, "User:", dbInfo.rows[0]?.user);
    console.log("Products count:", count.rows[0]?.products_count);
    console.log("Sample rows:");
    console.table(sample.rows);
  } catch (err) {
    console.error("Error running DB check:", err);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main();
