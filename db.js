/**
 * db.js — thin MySQL access layer over mysql2.
 *
 * A single pool is shared across requests. Helpers keep the route code short:
 * query() for SELECTs, execute() for writes (returns the new auto-increment
 * id), and audit() to append to the immutable audit log.
 */
const mysql = require("mysql2/promise");
const config = require("./config");

const pool = mysql.createPool({
  host: config.DB_HOST,
  port: config.DB_PORT,
  user: config.DB_USER,
  password: config.DB_PASSWORD,
  database: config.DB_NAME,
  charset: "utf8mb4_general_ci",
  waitForConnections: true,
  connectionLimit: 10,
});

async function query(sql, params = [], one = false) {
  const [rows] = await pool.query(sql, params);
  if (one) return rows.length ? rows[0] : null;
  return rows;
}

/** Run an INSERT/UPDATE/DELETE; return insertId (useful for inserts). */
async function execute(sql, params = []) {
  const [result] = await pool.query(sql, params);
  return result.insertId;
}

/** Append an immutable audit-log entry. Best-effort (never breaks a request). */
async function audit(userId, action, tableAffected = null, ip = null) {
  try {
    await execute(
      "INSERT INTO tbl_audit_logs (user_id, action_performed, table_affected, ip_address) " +
        "VALUES (?, ?, ?, ?)",
      [userId, action, tableAffected, ip]
    );
  } catch (e) {
    // swallow, matches Python's best-effort behavior
  }
}

module.exports = { pool, query, execute, audit };
