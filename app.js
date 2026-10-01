/**
 * app.js — Galaxy Trading backend (Express).
 *
 * Run:
 *     cd backend
 *     npm install
 *     node app.js
 * Then open  http://localhost:5000                    (customer storefront)
 *        and http://localhost:5000/staff/portal.html   (staff login)
 *
 * This single app serves BOTH the static frontend (the galaxytrading folder) and
 * the JSON API under /api, so there's only one thing to run and no CORS to fight.
 * The database lives in XAMPP's MySQL — import database/schema.sql via phpMyAdmin
 * first.
 */
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const multer = require("multer");

const config = require("./config");
const security = require("./security");
const auth = require("./auth");
const db = require("./db");
const integrations = require("./integrations");
const customers = require("./customers");
const twofactor = require("./twofactor");
const fabrication = require("./fabrication");
const suppliers = require("./suppliers");
const payments = require("./payments");
const mailer = require("./mailer");
// Storefront catalog, read for its list of customizable products.
const catalog = require("./products.js");
const stock = require("./stock");

const FRONTEND_DIR = path.resolve(__dirname, "..");
// UPLOAD_DIR in .env moves this onto a mounted disk for hosts with an
// ephemeral filesystem; left unset it stays inside the site folder.
const UPLOAD_DIR = config.UPLOAD_DIR
  ? path.resolve(config.UPLOAD_DIR)
  : path.join(FRONTEND_DIR, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();

// Behind Hostinger's proxy the real client IP and scheme arrive in
// X-Forwarded-* headers. Without this, rate limiting would see one shared IP
// and the HTTPS redirect could not tell http from https.
app.set("trust proxy", 1);

// --- security layer, before anything else can respond ----------------------
app.use(security.forceHttps);       // http -> https in production
app.use(security.securityHeaders);  // HSTS, CSP, nosniff, frame options
app.use(security.sameOriginCors);   // replaces the previous wide-open cors()

app.use(express.json({ limit: "2mb" }));          // cap the body size
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.use("/api", security.apiLimiter);             // blanket API rate limit

const upload = multer({ dest: UPLOAD_DIR });

// Checkout photos (customization reference + GCash receipt). Images only, 5MB
// cap, and the stored filename is generated - never taken from the upload.
const checkoutUpload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ok = ["image/jpeg", "image/jpg", "image/png"].includes(file.mimetype);
    cb(ok ? null : new Error("Only JPG, JPEG and PNG images are allowed."), ok);
  },
}).single("photo");

// Shared with the customers router, which owns the checkout endpoints.
app.locals.checkoutUpload = (req, res, next) =>
  checkoutUpload(req, res, (err) =>
    err ? res.status(400).json({ error: err.message }) : next());
/**
 * Keep an uploaded picture.
 *
 * It goes into MySQL, because a hosting container's filesystem is thrown away
 * on every restart and a customer's design must not be. A copy is also written
 * next to the site when that folder is writable, which keeps serving cheap.
 */
app.locals.saveUpload = async (file, name, userId) => {
  const bytes = fs.readFileSync(file.path);
  await db.execute(
    "INSERT INTO tbl_uploads (filename, mime_type, size_bytes, content, uploaded_by) " +
      "VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE content=VALUES(content), " +
      "  mime_type=VALUES(mime_type), size_bytes=VALUES(size_bytes)",
    [name, file.mimetype || "application/octet-stream", bytes.length, bytes, userId || null]
  );
  try {
    fs.renameSync(file.path, path.join(UPLOAD_DIR, name));
  } catch (e) {
    // Read-only or ephemeral disk: the database copy is the one that matters.
    try { fs.unlinkSync(file.path); } catch (e2) { /* nothing left to clean up */ }
  }
  return "uploads/" + name;
};

function clientIp(req) {
  return req.headers["x-forwarded-for"] || req.socket.remoteAddress;
}

function peso(n) {
  const num = parseFloat(n || 0);
  return "\u20B1" + num.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// Wrap async route handlers so rejected promises reach Express error handling.
function h(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

// ===========================================================================
//  RATE LIMITER — in-memory store (restart clears counts; fine for single-server)
// ===========================================================================
const loginLimiterMinute = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({ error: "Too many login attempts. Please wait a moment before trying again." }),
});
const loginLimiterHour = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).json({ error: "Too many login attempts. Please wait a moment before trying again." }),
});

// ===========================================================================
//  CUSTOMER ACCOUNTS  (storefront sign-up, profile, address book, order history)
//
//  Mounted before the static-file fallback so /api/account/* is handled here.
//  Sign-up shares the login rate limiters: it is the other way an attacker can
//  hammer tbl_users.
// ===========================================================================
app.use("/api/auth/register", loginLimiterMinute, loginLimiterHour);   // covers /register/start, /resend, /verify
app.use("/api/auth/customer/login", loginLimiterMinute, loginLimiterHour);
app.use(customers);
app.use(twofactor.router);   // 2FA enrolment + the second login step
app.use(fabrication);        // shop-floor queue, assignment, damage reports
app.use(suppliers);          // supplier directory (Administrator writes, others read)
app.use(payments);           // GCash references + the live transaction history

// ===========================================================================
//  AUTH  (staff portal authenticates here against MySQL tbl_users)
// ===========================================================================
app.post(
  "/api/auth/login",
  loginLimiterMinute,
  loginLimiterHour,
  h(async (req, res) => {
    const body = req.body || {};
    const username = (body.username || "").trim();
    const password = body.password || "";

    const cap = await integrations.verifyCaptcha(body.captcha_token || "", body.captcha_provider || "turnstile");
    if (!cap.ok) return res.status(400).json({ error: "Captcha verification failed" });

    const user = await db.query(
      "SELECT u.user_id, u.username, u.password_hash, u.full_name, u.is_active, " +
        "       u.totp_enabled, u.totp_secret, " +
        "       r.role_name FROM tbl_users u " +
        "JOIN tbl_roles r ON r.role_id = u.role_id WHERE u.username = ?",
      [username],
      true
    );
    if (!user || !user.is_active || !auth.verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: "Incorrect username or password" });
    }
    // Staff sign in here by username. Customers sign in on the storefront by
    // email (POST /api/auth/customer/login). Refusing them here keeps "email
    // only" true for customers — otherwise this route would be a way round it.
    // Same message as a wrong password, so it reveals nothing about the account.
    if (user.role_name === "Customer") {
      return res.status(401).json({ error: "Incorrect username or password" });
    }

    // Password was right. If this account has a second factor, stop here and
    // return a short-lived challenge - no session token is issued yet.
    if (twofactor.requiresTwoFactor(user)) {
      await db.audit(user.user_id, "Password accepted, awaiting 2FA code", "tbl_users", clientIp(req));
      return res.json(twofactor.challengeResponse(user));
    }

    await db.audit(user.user_id, `Logged in (${user.role_name})`, "tbl_users", clientIp(req));
    res.json({
      token: auth.issueToken(user, { remember: !!body.remember }),
      user: { user_id: user.user_id, username: user.username, full_name: user.full_name, role: user.role_name },
    });
  })
);

/**
 * Health check for the hosting platform (Render pings this). Deliberately
 * says nothing about the system beyond "the process is up and MySQL answers".
 */
app.get("/healthz", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.json({ ok: true, database: "up" });
  } catch (e) {
    res.status(503).json({ ok: false, database: "down", code: e.code, message: e.message });
  }
});

/**
 * How much of each catalog item is on the shelf.
 *
 * Public, because the storefront shows it next to every quantity box. It says
 * nothing beyond the count: no cost, no supplier, no reorder level. The sku
 * column holds the catalog's own variant id, so the two line up exactly.
 */
app.get(
  "/api/catalog/stock",
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT sku, stock_quantity FROM tbl_products WHERE status='active' AND sku IS NOT NULL AND sku <> ''"
    );
    const stock = {};
    for (const r of rows) stock[r.sku] = Math.max(0, Number(r.stock_quantity) || 0);
    // Never cached: the storefront must show what the Inventory holds now.
    res.set("Cache-Control", "no-store");
    res.json({ stock, count: rows.length, version: await stockVersion() });
  })
);

/**
 * A short string that changes whenever any product's stock does.
 *
 * The storefront asks for this every few seconds and re-reads the numbers only
 * when it moves, so an Inventory Manager's edit - or another customer's
 * checkout - reaches the shop pages within seconds without sending the whole
 * list over and over.
 */
async function stockVersion() {
  const row = await db.query(
    "SELECT COUNT(*) AS n, COALESCE(SUM(stock_quantity),0) AS q, " +
      "COALESCE(SUM(product_id * (stock_quantity + 1)),0) AS w, " +
      "COALESCE(SUM(status='active'),0) AS a " +
      "FROM tbl_products WHERE sku IS NOT NULL AND sku <> ''",
    [], true);
  return row ? `${row.n}-${row.q}-${row.w}-${row.a}` : "0";
}

app.get(
  "/api/catalog/stock/version",
  h(async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({ version: await stockVersion() });
  })
);

app.get("/api/auth/me", auth.loginRequired, (req, res) => {
  res.json({ user: req.user });
});

// ===========================================================================
//  SHARED SERVICES  (captcha)
// ===========================================================================
app.post(
  "/api/captcha/verify",
  h(async (req, res) => {
    const body = req.body || {};
    res.json(await integrations.verifyCaptcha(body.token || "", body.provider || "turnstile"));
  })
);

// ===========================================================================
//  ADMINISTRATOR
// ===========================================================================
app.get(
  "/api/admin/users",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT u.user_id, u.username, u.full_name, u.email, u.phone, " +
        "       u.is_active, r.role_name, u.created_at, " +
        // so the admin table can show who has a second factor, and offer to
        // clear it for anyone whose phone is lost or broken
        "       u.totp_enabled, u.totp_enrolled_at " +
        "FROM tbl_users u JOIN tbl_roles r ON r.role_id = u.role_id " +
        "ORDER BY u.user_id"
    );
    const roles = await db.query("SELECT role_id, role_name FROM tbl_roles ORDER BY role_id");
    res.json({ users: rows, roles });
  })
);

app.post(
  "/api/admin/users",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const b = req.body || {};
    if (!b.username || !b.password || !b.role_id) {
      return res.status(400).json({ error: "username, password and role_id are required" });
    }
    const pwErr = security.checkPasswordStrength(b.password, b.username);
    if (pwErr) return res.status(400).json({ error: pwErr });
    if (await db.query("SELECT 1 FROM tbl_users WHERE username=?", [b.username], true)) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const role = await db.query("SELECT role_name FROM tbl_roles WHERE role_id=?", [b.role_id], true);
    if (!role) return res.status(400).json({ error: "Choose a role for this account." });
    const isCustomer = role.role_name === "Customer";

    // Customers sign in with their email, so an account without one could never
    // be used. Staff sign in by username, where the email is optional.
    const email = String(b.email || "").trim().toLowerCase() || null;
    if (isCustomer && !email) {
      return res.status(400).json({ error: "A customer account needs an email address: it is their login." });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    if (email && (await db.query("SELECT 1 FROM tbl_users WHERE email=?", [email], true))) {
      return res.status(409).json({ error: "Another account already uses this email." });
    }

    const uid = await db.execute(
      "INSERT INTO tbl_users (username, password_hash, full_name, email, phone, role_id, email_verified_at) " +
        "VALUES (?,?,?,?,?,?,?)",
      [b.username, auth.hashPassword(b.password), b.full_name || null, email, b.phone || null, b.role_id,
       // The Administrator vouched for this address, so the customer does not
       // have to go through the sign-up code before they can log in.
       isCustomer ? new Date() : null]
    );
    await db.audit(req.user.user_id, `Created user '${b.username}'`, "tbl_users", clientIp(req));
    res.json({ ok: true, user_id: uid });
  })
);

app.patch(
  "/api/admin/users/:uid",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const uid = parseInt(req.params.uid, 10);
    const b = req.body || {};
    if ("is_active" in b) {
      await db.execute("UPDATE tbl_users SET is_active=? WHERE user_id=?", [b.is_active ? 1 : 0, uid]);
      await db.audit(
        req.user.user_id,
        `${b.is_active ? "Enabled" : "Disabled"} user #${uid}`,
        "tbl_users",
        clientIp(req)
      );
    }
    if ("role_id" in b) {
      await db.execute("UPDATE tbl_users SET role_id=? WHERE user_id=?", [b.role_id, uid]);
      await db.audit(req.user.user_id, `Changed role of user #${uid}`, "tbl_users", clientIp(req));
    }
    res.json({ ok: true });
  })
);

app.get(
  "/api/admin/audit-logs",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT a.log_id, a.action_performed, a.table_affected, a.ip_address, " +
        "       a.timestamp, u.username " +
        "FROM tbl_audit_logs a LEFT JOIN tbl_users u ON u.user_id = a.user_id " +
        "ORDER BY a.log_id DESC LIMIT 200"
    );
    res.json({ logs: rows });
  })
);

// ---------------------------------------------------------------------------
//  Shared SQL for the dashboard feeds. Each is used twice: once with LIMIT 5
//  for the compact card, once with a larger limit behind "View all".
// ---------------------------------------------------------------------------
const RECENT_ORDERS_SQL =
  "SELECT o.order_id, o.order_reference, o.order_date, o.total_amount, o.order_status, " +
  "       o.sale_type, COALESCE(u.full_name, u.username, 'Walk-in') AS customer " +
  "FROM tbl_orders o LEFT JOIN tbl_users u ON u.user_id = o.customer_id " +
  "ORDER BY o.order_date DESC, o.order_id DESC";

const RECENT_AUDIT_SQL =
  "SELECT a.log_id, a.action_performed, a.table_affected, a.ip_address, a.timestamp, " +
  "       u.username, u.full_name, r.role_name " +
  "FROM tbl_audit_logs a " +
  "LEFT JOIN tbl_users u ON u.user_id = a.user_id " +
  "LEFT JOIN tbl_roles r ON r.role_id = u.role_id " +
  "ORDER BY a.log_id DESC";

// Same feed, employees only: customers and unattributed rows are excluded, so
// "Recent User Activity" is strictly staff.
const STAFF_ACTIVITY_SQL =
  "SELECT a.log_id, a.action_performed, a.table_affected, a.ip_address, a.timestamp, " +
  "       u.username, u.full_name, r.role_name " +
  "FROM tbl_audit_logs a " +
  "JOIN tbl_users u ON u.user_id = a.user_id " +
  "JOIN tbl_roles r ON r.role_id = u.role_id " +
  "WHERE r.role_name <> 'Customer' " +
  "ORDER BY a.log_id DESC";

function orderRow(r) {
  return {
    id: r.order_id,
    ref: r.order_reference,
    customer: r.customer,
    status: r.order_status,
    sale_type: r.sale_type,
    total: parseFloat(r.total_amount || 0),
    date: r.order_date ? new Date(r.order_date).toISOString() : null,
  };
}

function auditRow(r) {
  return {
    id: r.log_id,
    action: r.action_performed,
    table: r.table_affected || "",
    ip: r.ip_address || "",
    user: r.full_name || r.username || "system",
    role: r.role_name || "",
    time: r.timestamp ? new Date(r.timestamp).toISOString() : null,
  };
}

// ---------------------------------------------------------------------------
//  VIEW ALL - the full list behind each dashboard card.
// ---------------------------------------------------------------------------
app.get(
  "/api/admin/reports/feed/:panel",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    // One page at a time: the audit trail alone is hundreds of rows, and the
    // dashboard's "View all" only ever shows one page of them.
    const perPage = Math.min(100, Math.max(1, parseInt(req.query.per_page || "20", 10)));
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const offset = (page - 1) * perPage;
    const panel = String(req.params.panel || "");

    const ALERTS_SQL =
      "SELECT material_id, material_name, stock_quantity, reorder_level, unit_of_measure " +
      "FROM tbl_raw_materials WHERE stock_quantity < reorder_level " +
      "ORDER BY (stock_quantity / NULLIF(reorder_level,0)) ASC";

    const PANELS = {
      orders: {
        title: "All Orders",
        sql: RECENT_ORDERS_SQL,
        count: "SELECT COUNT(*) c FROM tbl_orders",
        shape: orderRow,
      },
      audit: {
        title: "All Audit Logs",
        sql: RECENT_AUDIT_SQL,
        count: "SELECT COUNT(*) c FROM tbl_audit_logs",
        shape: auditRow,
      },
      activity: {
        title: "All Employee Activity",
        sql: STAFF_ACTIVITY_SQL,
        count: "SELECT COUNT(*) c FROM tbl_audit_logs a " +
               "JOIN tbl_users u ON u.user_id = a.user_id " +
               "JOIN tbl_roles r ON r.role_id = u.role_id WHERE r.role_name <> 'Customer'",
        shape: auditRow,
      },
      alerts: {
        title: "All Inventory Alerts",
        sql: ALERTS_SQL,
        count: "SELECT COUNT(*) c FROM tbl_raw_materials WHERE stock_quantity < reorder_level",
        shape: (m) => ({
          name: m.material_name,
          unit: m.unit_of_measure,
          stock: parseFloat(m.stock_quantity),
          reorder: parseFloat(m.reorder_level),
          deficit: Math.round((parseFloat(m.reorder_level) - parseFloat(m.stock_quantity)) * 100) / 100,
        }),
      },
    };

    const view = PANELS[panel];
    if (!view) return res.status(404).json({ error: "Unknown panel: " + panel });

    const total = ((await db.query(view.count, [], true)) || {}).c || 0;
    // LIMIT/OFFSET are numbers this function computed, never text from the URL.
    const rows = await db.query(`${view.sql} LIMIT ${perPage} OFFSET ${offset}`);
    res.json({
      panel,
      title: view.title,
      rows: rows.map(view.shape),
      page,
      per_page: perPage,
      total,
      pages: Math.max(1, Math.ceil(total / perPage)),
    });
  })
);

// ---------------------------------------------------------------------------
//  ADMIN REPORTS — every figure is aggregated live from MySQL. Nothing here is
//  sample data: the charts on the admin dashboard read straight from this.
// ---------------------------------------------------------------------------
app.get(
  "/api/admin/reports",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const num = (v) => (v === null || v === undefined ? 0 : parseFloat(v));

    // --- inventory: stock against reorder level -----------------------------
    const materials = await db.query(
      "SELECT material_id, material_name, stock_quantity, reorder_level, unit_of_measure " +
        "FROM tbl_raw_materials ORDER BY material_name"
    );
    const inventory = materials.map((m) => {
      const stock = num(m.stock_quantity);
      const reorder = num(m.reorder_level);
      return {
        material_id: m.material_id,
        name: m.material_name,
        unit: m.unit_of_measure,
        stock,
        reorder,
        deficit: stock < reorder ? Math.round((reorder - stock) * 100) / 100 : 0,
        // How much of the reorder level is still covered — drives the urgency badge.
        pct: reorder > 0 ? Math.round((stock / reorder) * 1000) / 10 : null,
        low: stock < reorder,
      };
    });

    // --- suppliers, with how many purchase orders each has -------------------
    const suppliers = await db.query(
      "SELECT s.supplier_id, s.supplier_name, s.contact_person, s.phone, s.email, " +
        "       s.materials_supplied, " +
        "       COUNT(po.po_id)                                          AS po_count, " +
        "       SUM(CASE WHEN po.status = 'pending' THEN 1 ELSE 0 END)    AS po_pending, " +
        "       MAX(po.order_date)                                        AS last_order " +
        "FROM tbl_suppliers s " +
        "LEFT JOIN tbl_purchase_orders po ON po.supplier_id = s.supplier_id " +
        "GROUP BY s.supplier_id ORDER BY s.supplier_name"
    );

    // --- orders by status ---------------------------------------------------
    const byStatus = await db.query(
      "SELECT order_status AS status, COUNT(*) AS count, SUM(total_amount) AS amount " +
        "FROM tbl_orders GROUP BY order_status ORDER BY COUNT(*) DESC"
    );

    // --- revenue trend, most recent 12 months last --------------------------
    const trend = await db.query(
      "SELECT DATE_FORMAT(order_date, '%Y-%m') AS month, " +
        "       COUNT(*) AS orders, SUM(total_amount) AS revenue " +
        "FROM tbl_orders GROUP BY month ORDER BY month DESC LIMIT 12"
    );

    // --- best sellers by revenue -------------------------------------------
    const topProducts = await db.query(
      "SELECT p.product_name AS name, SUM(oi.quantity) AS units, SUM(oi.subtotal) AS revenue " +
        "FROM tbl_order_items oi JOIN tbl_products p ON p.product_id = oi.product_id " +
        "GROUP BY p.product_id ORDER BY revenue DESC LIMIT 8"
    );

    // --- best sellers by UNITS (a different story from revenue) -------------
    const bestSellers = await db.query(
      "SELECT p.product_name AS name, SUM(oi.quantity) AS units, SUM(oi.subtotal) AS revenue " +
        "FROM tbl_order_items oi JOIN tbl_products p ON p.product_id = oi.product_id " +
        "GROUP BY p.product_id ORDER BY units DESC LIMIT 6"
    );

    // --- how many distinct items each supplier provides ---------------------
    // Purchase orders are the real link. Until any exist, fall back to counting
    // the comma-separated entries in tbl_suppliers.materials_supplied so the
    // chart still says something truthful about the data on hand.
    const supplierItems = await db.query(
      "SELECT s.supplier_id, s.supplier_name AS name, " +
        "       COUNT(DISTINCT COALESCE(po.product_id, po.material_id)) AS po_items, " +
        "       COUNT(po.po_id) AS po_count, s.materials_supplied " +
        "FROM tbl_suppliers s LEFT JOIN tbl_purchase_orders po ON po.supplier_id = s.supplier_id " +
        "GROUP BY s.supplier_id ORDER BY s.supplier_name"
    );

    // --- recent activity feeds ---------------------------------------------
    const latestOrders = await db.query(RECENT_ORDERS_SQL + " LIMIT 5");
    const recentAudit = await db.query(RECENT_AUDIT_SQL + " LIMIT 5");
    const recentActivity = await db.query(STAFF_ACTIVITY_SQL + " LIMIT 5");

    const totals =
      (await db.query(
        "SELECT (SELECT COUNT(*) FROM tbl_orders)        AS orders, " +
          "       (SELECT SUM(total_amount) FROM tbl_orders) AS revenue, " +
          "       (SELECT COUNT(*) FROM tbl_products)        AS products, " +
          "       (SELECT COUNT(*) FROM tbl_suppliers)       AS suppliers",
        [],
        true
      )) || {};

    res.json({
      summary: {
        orders: num(totals.orders),
        revenue: num(totals.revenue),
        products: num(totals.products),
        suppliers: num(totals.suppliers),
        materials: inventory.length,
        low_stock: inventory.filter((m) => m.low).length,
      },
      inventory,
      suppliers: suppliers.map((s) => ({
        supplier_id: s.supplier_id,
        name: s.supplier_name,
        contact: s.contact_person || "",
        phone: s.phone || "",
        email: s.email || "",
        materials: s.materials_supplied || "",
        po_count: num(s.po_count),
        po_pending: num(s.po_pending),
        last_order: s.last_order ? new Date(s.last_order).toISOString() : null,
      })),
      orders_by_status: byStatus.map((r) => ({
        status: r.status,
        count: num(r.count),
        amount: num(r.amount),
      })),
      revenue_trend: trend
        .map((r) => ({ month: r.month, orders: num(r.orders), revenue: num(r.revenue) }))
        .reverse(),
      top_products: topProducts.map((r) => ({
        name: r.name,
        units: num(r.units),
        revenue: num(r.revenue),
      })),
      best_sellers: bestSellers.map((r) => ({
        name: r.name,
        units: num(r.units),
        revenue: num(r.revenue),
      })),
      products_by_supplier: supplierItems.map((r) => {
        const listed = String(r.materials_supplied || "")
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean).length;
        const fromPos = num(r.po_items);
        return {
          name: r.name,
          items: fromPos || listed,
          po_count: num(r.po_count),
          // Tells the UI whether this number came from real purchase orders.
          source: fromPos ? "purchase_orders" : "materials_listed",
        };
      }),
      latest_orders: latestOrders.map(orderRow),
      recent_audit: recentAudit.map(auditRow),
      recent_activity: recentActivity.map(auditRow),
    });
  })
);

app.get(
  "/api/admin/health",
  auth.requireRole("Administrator"),
  h(async (req, res) => {
    const t0 = Date.now();
    let dbMs = null;
    let dbOk = true;
    try {
      await db.query("SELECT 1", [], true);
      dbMs = Math.round((Date.now() - t0) * 10) / 10;
    } catch (e) {
      dbMs = null;
      dbOk = false;
    }
    const counts = {
      users: ((await db.query("SELECT COUNT(*) c FROM tbl_users", [], true)) || {}).c || 0,
      orders: ((await db.query("SELECT COUNT(*) c FROM tbl_orders", [], true)) || {}).c || 0,
      pending_orders:
        ((await db.query("SELECT COUNT(*) c FROM tbl_orders WHERE order_status='pending'", [], true)) || {}).c || 0,
    };
    res.json({
      services: {
        "MySQL Database": { ok: dbOk, latency_ms: dbMs },
        Captcha: { ok: true, enforced: config.CAPTCHA_REQUIRED },
        // Storefront sign-up cannot finish without it: the OTP is emailed via
        // Gmail or Resend. Unset means codes only print in the server terminal.
        ["Email (" + mailer.providerLabel() + ")"]: { ok: mailer.isConfigured(), configured: mailer.isConfigured() },
      },
      counts,
    });
  })
);

// ===========================================================================
//  SALES MANAGER
// ===========================================================================
app.get(
  "/api/sales/orders",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const status = req.query.status;
    let sql =
      "SELECT o.order_id, o.order_reference, o.order_date, o.total_amount, " +
      "       o.order_status, o.delivery_address, o.latitude, o.longitude, o.notes, " +
      "       u.full_name AS customer_name, u.phone AS customer_phone, u.email AS customer_email " +
      "FROM tbl_orders o JOIN tbl_users u ON u.user_id = o.customer_id ";
    const params = [];
    if (status) {
      sql += "WHERE o.order_status = ? ";
      params.push(status);
    }
    sql += "ORDER BY o.order_date DESC";
    res.json({ orders: await db.query(sql, params) });
  })
);

app.get(
  "/api/sales/orders/:oid",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const oid = parseInt(req.params.oid, 10);
    const order = await db.query(
      "SELECT o.*, u.full_name AS customer_name, u.phone AS customer_phone, " +
        "       u.email AS customer_email FROM tbl_orders o " +
        "JOIN tbl_users u ON u.user_id = o.customer_id WHERE o.order_id=?",
      [oid],
      true
    );
    if (!order) return res.status(404).json({ error: "Order not found" });
    const items = await db.query(
      "SELECT oi.order_item_id, oi.quantity, oi.unit_price, oi.subtotal, " +
        "       COALESCE(p.product_name, oi.item_description) AS product_name, " +
        "       cj.cutting_length_meters, cj.number_of_cuts, cj.bending_angle_degrees, " +
        "       cj.number_of_bends, cj.design_file_path " +
        "FROM tbl_order_items oi LEFT JOIN tbl_products p ON p.product_id = oi.product_id " +
        "LEFT JOIN tbl_custom_jobs cj ON cj.order_item_id = oi.order_item_id " +
        "WHERE oi.order_id=?",
      [oid]
    );
    res.json({ order, items });
  })
);

app.post(
  "/api/sales/orders/:oid/decision",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const oid = parseInt(req.params.oid, 10);
    const b = req.body || {};
    const decision = b.decision;
    if (!["approve", "reject"].includes(decision)) {
      return res.status(400).json({ error: "decision must be 'approve' or 'reject'" });
    }
    const newStatus = decision === "approve" ? "approved" : "rejected";
    await db.execute("UPDATE tbl_orders SET order_status=? WHERE order_id=?", [newStatus, oid]);

    if (decision === "approve") {
      const jobs = await db.query(
        "SELECT cj.custom_job_id FROM tbl_custom_jobs cj " +
          "JOIN tbl_order_items oi ON oi.order_item_id = cj.order_item_id " +
          "WHERE oi.order_id=?",
        [oid]
      );
      for (const j of jobs) {
        const exists = await db.query(
          "SELECT 1 FROM tbl_fabrication_logs WHERE custom_job_id=?",
          [j.custom_job_id],
          true
        );
        if (!exists) {
          await db.execute(
            "INSERT INTO tbl_fabrication_logs (custom_job_id, production_status) VALUES (?,'queued')",
            [j.custom_job_id]
          );
        }
      }
      await db.execute("UPDATE tbl_orders SET order_status='in_production' WHERE order_id=?", [oid]);
    }

    await db.audit(
      req.user.user_id,
      `${decision.charAt(0).toUpperCase() + decision.slice(1)}d order #${oid}`,
      "tbl_orders",
      clientIp(req)
    );
    res.json({ ok: true, status: newStatus });
  })
);

app.get(
  "/api/sales/metrics",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    const revenue =
      ((await db.query(
        "SELECT COALESCE(SUM(total_amount),0) s FROM tbl_orders WHERE order_status NOT IN ('rejected','cancelled')",
        [],
        true
      )) || {}).s || 0;
    const trend = await db.query(
      "SELECT DATE(order_date) d, COALESCE(SUM(total_amount),0) s " +
        "FROM tbl_orders WHERE order_date >= (CURDATE() - INTERVAL 6 DAY) " +
        "GROUP BY DATE(order_date) ORDER BY d"
    );
    const byStatus = await db.query("SELECT order_status s, COUNT(*) c FROM tbl_orders GROUP BY order_status");
    const pending =
      ((await db.query("SELECT COUNT(*) c FROM tbl_orders WHERE order_status='pending'", [], true)) || {}).c || 0;
    res.json({ total_revenue: parseFloat(revenue), pending, trend, by_status: byStatus });
  })
);

// ----- Walk-in POS (Sales Manager "Transaction UI") ------------------------
app.get(
  "/api/sales/products",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    res.json({
      products: await db.query("SELECT product_id, product_name, base_price, stock_quantity FROM tbl_products ORDER BY product_name"),
    });
  })
);

/**
 * Item History — every time the shelf moved, newest first.
 *
 * One row per product per sale: what it was, what was taken, what is left, the
 * order it belonged to, whether it came from the storefront or the counter,
 * and who was at the keyboard. Read by the Inventory Manager panel.
 *
 * ?source=online|walkin|return   ?q=<item name or reference>   ?limit=<n>
 */
app.get(
  "/api/inventory/history",
  auth.requireRole("Inventory Manager", "Administrator", "Sales Manager"),
  h(async (req, res) => {
    const where = ["m.item_type='product'"];
    const params = [];
    const source = String(req.query.source || "").trim();
    if (["online", "walkin", "return"].includes(source)) {
      where.push("m.source=?");
      params.push(source);
    }
    const q = String(req.query.q || "").trim();
    if (q) {
      where.push("(m.item_name LIKE ? OR m.reference LIKE ?)");
      params.push("%" + q + "%", "%" + q + "%");
    }
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 200));

    const rows = await db.query(
      "SELECT m.movement_id, m.item_id, m.item_name, m.movement, m.source, m.quantity, " +
        "       m.stock_before, m.stock_after, m.reference, m.note, m.created_at, " +
        "       COALESCE(u.full_name, m.performed_by) AS performed_by " +
        "FROM tbl_stock_movements m " +
        "LEFT JOIN tbl_users u ON u.username = m.performed_by " +
        "WHERE " + where.join(" AND ") +
        " ORDER BY m.created_at DESC, m.movement_id DESC LIMIT " + limit,
      params
    );

    res.set("Cache-Control", "no-store");
    res.json({
      history: rows.map((r) => ({
        id: r.movement_id,
        product_id: r.item_id,
        item: r.item_name,
        movement: r.movement,                       // 'out' when sold, 'in' when returned
        source: r.source || "",                     // 'online' | 'walkin' | 'return'
        quantity: Number(r.quantity) || 0,
        stock_before: r.stock_before == null ? null : Number(r.stock_before),
        stock_after: Number(r.stock_after) || 0,
        reference: r.reference || "",
        note: r.note || "",
        by: r.performed_by || "",
        at: new Date(r.created_at).toISOString(),
      })),
      count: rows.length,
    });
  })
);

app.get(
  "/api/sales/config",
  auth.requireRole("Sales Manager", "Administrator"),
  (req, res) => {
    res.json({ business: config.BUSINESS, vat_rate: config.VAT_RATE, delivery_fee: config.DELIVERY_FEE });
  }
);

async function nextInvoiceNo() {
  await db.execute("UPDATE tbl_counters SET value = value + 1 WHERE counter_name='invoice'");
  const row = await db.query("SELECT value FROM tbl_counters WHERE counter_name='invoice'", [], true);
  const n = row ? row.value : 1;
  return "GT-" + String(n).padStart(6, "0");
}

function binasciiToken() {
  return require("crypto").randomBytes(12).toString("hex");
}

async function walkinCustomer(name, phone) {
  const existing = await db.query("SELECT user_id FROM tbl_users WHERE phone=? AND role_id=6", [phone], true);
  if (existing) return existing.user_id;
  const digits = (phone || "").replace(/\D/g, "").slice(-9);
  const base = digits ? "walkin_" + digits : "walkin";
  let username = base;
  let n = 1;
  while (await db.query("SELECT 1 FROM tbl_users WHERE username=?", [username], true)) {
    n += 1;
    username = `${base}_${n}`;
  }
  return db.execute(
    "INSERT INTO tbl_users (username, password_hash, full_name, phone, role_id) VALUES (?,?,?,?,6)",
    [username, auth.hashPassword(binasciiToken()), name, phone]
  );
}

app.post(
  "/api/sales/pos",
  auth.requireRole("Sales Manager", "Administrator"),
  h(async (req, res) => {
    /*
     * Create a walk-in sale. VAT-inclusive math. On success the order is
     * marked paid and pushed to fabrication (if it has custom jobs) or
     * delivery, exactly like an approved online order. There is no extra
     * confirmation step for large sales any more.
     */
    const b = req.body || {};
    const cust = b.customer || {};
    const items = b.items || [];
    const name = (cust.name || "").trim();
    const phone = (cust.phone || "").trim();
    if (!name || !phone) return res.status(400).json({ error: "Customer name and phone are required" });
    if (!items.length) return res.status(400).json({ error: "Add at least one item to the sale" });

    // ---- totals (VAT-inclusive) ----
    let gross = 0.0;
    let deliveryLines = 0;
    for (const it of items) {
      // The delivery fee is a normal sale line, but its amount is the shop's
      // fixed fee — whatever the page sent for price or quantity is ignored.
      if (it.kind === "delivery") {
        deliveryLines += 1;
        it.qty = 1;
        it.unit_price = config.DELIVERY_FEE;
        it._desc = "Delivery Fee";
      }
      const qty = parseFloat(it.qty || 0);
      const price = parseFloat(it.unit_price || 0);
      if (qty <= 0 || price < 0) {
        return res.status(400).json({ error: "Each line needs a positive quantity and price" });
      }
      // A custom cut/bend job must name the customizable product it is made
      // from. Anything not in CUSTOMIZABLE_NAMES (products.js) is refused.
      if ((it.kind || "product") === "custom") {
        const prod = catalog.PRODUCTS.find((p) => p.id === String(it.catalog_id || ""));
        if (!prod || !prod.customizable) {
          return res.status(400).json({
            error: "Custom cut/bend is only for these products: " +
                   catalog.CUSTOMIZABLE_NAMES.join(", ") + ". Choose one for each custom job.",
          });
        }
        const variant = [prod.size, prod.color && "(" + prod.color + ")"].filter(Boolean).join(" ");
        // Written by the server so the receipt and the fabrication queue always
        // say which item is being cut or bent.
        it._desc = `${prod.name} ${variant} — custom cut/bend`.slice(0, 255);
        // The instructions are for the shop floor only: kept on the custom job
        // and shown in the Fabrication Panel, never printed on the receipt.
        it._notes = String(it.notes || "").trim().slice(0, 500) || null;
      }
      it._qty = qty;
      it._price = price;
      it._sub = Math.round(qty * price * 100) / 100;
      gross += it._sub;
    }
    // Custom work can be handed to the floor straight from the counter: one
    // main fabricator, plus up to two helpers.
    const assignTo = b.assign_to ? parseInt(b.assign_to, 10) : null;
    if (assignTo) {
      const who = await db.query(
        "SELECT u.user_id FROM tbl_users u JOIN tbl_roles r ON r.role_id=u.role_id " +
          "WHERE u.user_id=? AND u.is_active=1 AND r.role_name IN ('Fabrication','Employee')",
        [assignTo], true);
      if (!who) return res.status(400).json({ error: "That user is not a fabrication employee." });
    }
    const helpers = await fabrication.readHelpers(b, assignTo);
    if (helpers.error) return res.status(400).json({ error: helpers.error });

    if (deliveryLines > 1) {
      return res.status(400).json({ error: "Add the delivery fee only once per sale." });
    }
    if (deliveryLines && !String(cust.address || "").trim()) {
      return res.status(400).json({ error: "Enter the customer's delivery address for a sale with delivery." });
    }
    const discount = parseFloat(b.discount_amount || 0);
    const totalDue = Math.round(Math.max(gross - discount, 0) * 100) / 100;
    const vatable = Math.round((totalDue / (1 + config.VAT_RATE)) * 100) / 100;
    const vat = Math.round((totalDue - vatable) * 100) / 100;

    // ---- money received, and the customer's change ----
    // Left blank, the customer is taken to have paid the exact amount.
    const paidRaw = b.amount_paid === undefined || b.amount_paid === null || b.amount_paid === ""
      ? totalDue : parseFloat(b.amount_paid);
    if (!Number.isFinite(paidRaw) || paidRaw < 0) {
      return res.status(400).json({ error: "Enter the amount the customer paid." });
    }
    const amountPaid = Math.round(paidRaw * 100) / 100;
    if (amountPaid < totalDue) {
      return res.status(400).json({
        error: `The amount paid is short by ${peso(totalDue - amountPaid)}.`,
      });
    }
    const change = Math.round((amountPaid - totalDue) * 100) / 100;

    // A sale is a delivery only if the Delivery Fee was added; otherwise the
    // customer takes it from the shop and nothing goes to the Delivery panel.
    const fulfillment = deliveryLines ? "delivery" : "pickup";

    // ---- payment channel ----
    // Cash or GCash; there is no card terminal in the shop. A GCash sale needs
    // a reference number, and a reference already claimed by another order is
    // recorded rather than refused — see payments.js for why.
    const channel = String(b.payment_channel || b.payment_method || "cash").toLowerCase() === "gcash"
      ? "gcash" : "cash";
    let gcashRef = null;
    let duplicateOf = [];
    if (channel === "gcash") {
      const v = payments.normaliseReference(b.gcash_reference);
      if (!v.ok) return res.status(400).json({ error: v.error });
      gcashRef = v.ref;
      duplicateOf = await payments.findReferenceUses(gcashRef);
    }

    // ---- persist ----
    const customerId = await walkinCustomer(name, phone);
    const invoiceNo = await nextInvoiceNo();
    const orderId = await db.execute(
      "INSERT INTO tbl_orders (customer_id, order_reference, invoice_no, sale_type, fulfillment, " +
        " order_date, total_amount, discount_amount, vatable_sales, vat_amount, amount_paid, " +
        " payment_method, payment_channel, gcash_reference, payment_status, " +
        " order_status, delivery_address, customer_tin, business_address) " +
        "VALUES (?,?,?,'walkin',?,NOW(),?,?,?,?,?,?,?,?,?,'approved',?,?,?)",
      [
        customerId,
        invoiceNo,
        invoiceNo,
        fulfillment,
        totalDue,
        discount,
        vatable,
        vat,
        amountPaid,
        channel,
        channel,
        gcashRef,
        // Cash is handed over at the counter, so it is settled. A GCash
        // transfer is only a claim until somebody checks it arrived.
        channel === "gcash" ? "pending_verification" : "paid",
        cust.address || null,
        cust.tin || null,
        cust.address || null,
      ]
    );

    let hasCustom = false;
    for (const it of items) {
      const kind = it.kind || "product";
      // A custom job is cut from a real product, so it carries (and draws
      // stock from) that product too. Manual lines have no product.
      const pid = kind === "manual" || kind === "delivery" ? null : (parseInt(it.product_id, 10) || null);
      const desc = it._desc || it.name || it.description;
      const oiid = await db.execute(
        "INSERT INTO tbl_order_items (order_id, product_id, item_description, quantity, " +
          " unit_price, subtotal) VALUES (?,?,?,?,?,?)",
        [orderId, pid || null, desc, it._qty, it._price, it._sub]
      );
      if (pid) {
        // Draw the shelf and write the Item History line in one place, so a
        // walk-in sale and an accepted online order leave the same trail.
        const drawn = await stock.draw(db.pool.query.bind(db.pool), {
          productId: pid, qty: it._qty, source: "walkin",
          reference: invoiceNo, by: req.user.username,
          note: `Walk-in sale (${desc || "item"})`,
        });
        if (!drawn.ok && !drawn.missing) {
          // The shelf moved between the cart and the receipt. The sale stands -
          // the goods are over the counter - so the shortfall is recorded
          // rather than hidden, and the floor is left at zero.
          await db.execute(
            "UPDATE tbl_products SET stock_quantity = 0 WHERE product_id=?", [pid]);
          await stock.record(db.pool.query.bind(db.pool), {
            productId: pid, name: desc || "Item", movement: "out", source: "walkin",
            qty: it._qty, before: drawn.left, after: 0, reference: invoiceNo,
            note: "Walk-in sale — only " + drawn.left + " were on the shelf",
            by: req.user.username,
          });
        }
      }
      if (kind === "custom") {
        const cj = await db.execute(
          "INSERT INTO tbl_custom_jobs (order_item_id, cutting_length_meters, number_of_cuts, " +
            " bending_angle_degrees, number_of_bends, instructions, design_file_path) VALUES (?,?,?,?,?,?,?)",
          [
            oiid,
            it.cutting_length_meters ?? null,
            it.number_of_cuts ?? null,
            it.bending_angle_degrees ?? null,
            it.number_of_bends ?? null,
            it._notes ?? null,
            it.design_file_path ?? null,
          ]
        );
        await db.execute(
          "INSERT INTO tbl_fabrication_logs (custom_job_id, production_status, " +
            " assigned_to, helper_1, helper_2, assigned_by, assigned_at) " +
            "VALUES (?,'queued',?,?,?,?,?)",
          [cj, assignTo, helpers.h1, helpers.h2,
           assignTo ? req.user.user_id : null, assignTo ? new Date() : null]);
        hasCustom = true;
      }
    }

    // ---- route it like an approved order ----
    // Custom work goes to Fabrication first (and on to delivery when it is done,
    // if this is a delivery). Otherwise a delivery is queued for the Delivery
    // panel now, and a pick-up is simply ready at the counter.
    if (hasCustom) {
      await db.execute("UPDATE tbl_orders SET order_status='in_production' WHERE order_id=?", [orderId]);
    } else {
      await db.execute("UPDATE tbl_orders SET order_status='ready' WHERE order_id=?", [orderId]);
      if (fulfillment === "delivery") {
        await db.execute("INSERT INTO tbl_deliveries (order_id, delivery_status) VALUES (?,'queued')", [orderId]);
      }
    }

    await db.audit(req.user.user_id, `Walk-in sale ${invoiceNo} (${peso(totalDue)})`, "tbl_orders", clientIp(req));

    const receipt = {
      invoice_no: invoiceNo,
      order_id: orderId,
      date: new Date().toISOString().slice(0, 16).replace("T", " "),
      cashier: req.user.username,
      customer: { name, phone, tin: cust.tin, address: cust.address },
      items: items.map((it) => ({
        description: it._desc || it.name || it.description,
        qty: it._qty,
        unit_price: it._price,
        amount: it._sub,
      })),
      gross: Math.round(gross * 100) / 100,
      discount,
      vatable_sales: vatable,
      vat,
      total_due: totalDue,
      amount_paid: amountPaid,
      change,
      fulfillment,
      // What the receipt prints on its "Fulfilment" line.
      assigned_to: assignTo,
      helper_names: helpers.names,
      routed_to: (hasCustom ? "Fabrication, then " : "") +
                 (fulfillment === "delivery" ? "delivery" : "pick-up at the shop"),
      business: config.BUSINESS,
      vat_rate: config.VAT_RATE,
      payment_channel: channel,
      gcash_reference: gcashRef,
    };
    // The sale is saved either way; the warning is so the cashier can query it
    // with the customer while they are still at the counter.
    res.json({
      ok: true,
      receipt,
      duplicate_reference: duplicateOf.length > 0,
      duplicate_with: duplicateOf,
    });
  })
);

// ===========================================================================
//  INVENTORY MANAGER
// ===========================================================================
app.get(
  "/api/inventory/raw-materials",
  // Read-only. The shop floor needs stock and reorder levels to judge whether a
  // job can start; changing those figures stays with Inventory (PATCH below).
  auth.requireRole("Inventory Manager", "Administrator", "Sales Manager", "Employee", "Fabrication"),
  h(async (req, res) => {
    res.json({ materials: await db.query("SELECT * FROM tbl_raw_materials ORDER BY material_name") });
  })
);

app.patch(
  "/api/inventory/raw-materials/:mid",
  auth.requireRole("Inventory Manager", "Administrator"),
  h(async (req, res) => {
    const mid = parseInt(req.params.mid, 10);
    const b = req.body || {};
    const fields = [];
    const params = [];
    for (const col of ["stock_quantity", "reorder_level"]) {
      if (col in b) {
        fields.push(`${col}=?`);
        params.push(b[col]);
      }
    }
    if (!fields.length) return res.status(400).json({ error: "Nothing to update" });
    params.push(mid);
    await db.execute(`UPDATE tbl_raw_materials SET ${fields.join(", ")} WHERE material_id=?`, params);
    await db.audit(req.user.user_id, `Adjusted raw material #${mid}`, "tbl_raw_materials", clientIp(req));
    res.json({ ok: true });
  })
);

app.get(
  "/api/inventory/products",
  auth.requireRole("Inventory Manager", "Administrator"),
  h(async (req, res) => {
    res.json({ products: await db.query("SELECT * FROM tbl_products ORDER BY product_name") });
  })
);

app.get(
  "/api/inventory/scrap",
  auth.requireRole("Inventory Manager", "Administrator"),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT f.fab_log_id, f.scrap_waste_generated, f.completion_timestamp, " +
        "       f.production_status, cj.cutting_length_meters, u.full_name AS operator " +
        "FROM tbl_fabrication_logs f " +
        "JOIN tbl_custom_jobs cj ON cj.custom_job_id = f.custom_job_id " +
        "LEFT JOIN tbl_users u ON u.user_id = f.employee_id " +
        "WHERE f.scrap_waste_generated > 0 ORDER BY f.fab_log_id DESC"
    );
    const total = rows.reduce((s, r) => s + parseFloat(r.scrap_waste_generated || 0), 0);
    res.json({ reports: rows, total_scrap: Math.round(total * 100) / 100 });
  })
);

app.get(
  "/api/inventory/alerts",
  // Sales Manager is included deliberately: the sales dashboard shows a
  // low-stock panel so they know what not to promise a customer. It is
  // read-only — the inventory WRITE endpoints stay Inventory Manager only.
  auth.requireRole("Inventory Manager", "Sales Manager", "Administrator"),
  h(async (req, res) => {
    const low = await db.query(
      "SELECT material_id, material_name, stock_quantity, reorder_level, unit_of_measure " +
        "FROM tbl_raw_materials WHERE stock_quantity <= reorder_level " +
        "ORDER BY (stock_quantity - reorder_level)"
    );
    res.json({ low_stock: low, count: low.length });
  })
);

// ===========================================================================
//  EMPLOYEE (FABRICATION)
// ===========================================================================
// The queue, job detail, history, assignment and damage reports now live in
// fabrication.js, which serves storefront and walk-in orders from one list.
// What stays here is the status machine and the shop-floor notes.

// Shop-floor notes against a job.
app.post(
  "/api/fabrication/jobs/:fid/notes",
  auth.requireRole("Employee", "Fabrication", "Administrator"),
  h(async (req, res) => {
    const fid = parseInt(req.params.fid, 10);
    const notes = String((req.body || {}).notes || "").slice(0, 4000);
    await db.execute("UPDATE tbl_fabrication_logs SET fabrication_notes=? WHERE fab_log_id=?", [notes, fid]);
    await db.audit(req.user.user_id, `Updated fabrication notes on job #${fid}`, "tbl_fabrication_logs", clientIp(req));
    res.json({ ok: true });
  })
);

app.post(
  "/api/fabrication/jobs/:fid/status",
  auth.requireRole("Employee", "Fabrication", "Administrator"),
  h(async (req, res) => {
    const fid = parseInt(req.params.fid, 10);
    const b = req.body || {};
    const action = b.action; // start | pause | resume | send_qa | qa_fail | complete

    // The main fabricator owns the job's progress. A helper can see it and
    // report damage on it, but cannot start, pause or finish it.
    const own = await db.query(
      "SELECT assigned_to, helper_1, helper_2 FROM tbl_fabrication_logs WHERE fab_log_id=?",
      [fid], true);
    if (!own) return res.status(404).json({ error: "Job not found" });
    const isHelper = own.helper_1 === req.user.user_id || own.helper_2 === req.user.user_id;
    if (isHelper && own.assigned_to !== req.user.user_id && req.user.role !== "Administrator") {
      return res.status(403).json({
        error: "You are a helper on this job. Only the main fabrication staff can change its status.",
      });
    }

    if (action === "start") {
      await db.execute(
        "UPDATE tbl_fabrication_logs SET production_status='in_progress', " +
          "started_at=NOW(), employee_id=? WHERE fab_log_id=?",
        [req.user.user_id, fid]
      );
      await db.audit(req.user.user_id, `Started fabrication #${fid}`, "tbl_fabrication_logs", clientIp(req));
    } else if (action === "complete") {
      const scrap = b.scrap_waste_generated || 0;
      await db.execute(
        "UPDATE tbl_fabrication_logs SET production_status='completed', " +
          "completion_timestamp=NOW(), scrap_waste_generated=?, employee_id=? " +
          "WHERE fab_log_id=?",
        [scrap, req.user.user_id, fid]
      );
      // A storefront order finishes differently: there is no tbl_orders row to
      // move, so the online order is marked ready and the Sales Manager decides
      // when to release it to the delivery panel.
      const online = await db.query(
        "SELECT online_order_id FROM tbl_fabrication_logs WHERE fab_log_id=?", [fid], true);
      if (online && online.online_order_id) {
        const left = await db.query(
          "SELECT COUNT(*) c FROM tbl_fabrication_logs " +
            "WHERE online_order_id=? AND production_status <> 'completed'",
          [online.online_order_id], true);
        if (left && left.c === 0) {
          await db.execute(
            "UPDATE tbl_online_orders SET status='ready_for_delivery', fabrication_done_at=NOW() " +
              "WHERE online_order_id=?",
            [online.online_order_id]);
        }
      }

      const order = await db.query(
        "SELECT o.order_id, o.fulfillment FROM tbl_fabrication_logs f " +
          "JOIN tbl_custom_jobs cj ON cj.custom_job_id=f.custom_job_id " +
          "JOIN tbl_order_items oi ON oi.order_item_id=cj.order_item_id " +
          "JOIN tbl_orders o ON o.order_id=oi.order_id WHERE f.fab_log_id=?",
        [fid],
        true
      );
      if (order) {
        const remaining = await db.query(
          "SELECT COUNT(*) c FROM tbl_fabrication_logs f " +
            "JOIN tbl_custom_jobs cj ON cj.custom_job_id=f.custom_job_id " +
            "JOIN tbl_order_items oi ON oi.order_item_id=cj.order_item_id " +
            "WHERE oi.order_id=? AND f.production_status NOT IN ('completed')",
          [order.order_id],
          true
        );
        if (remaining && remaining.c === 0) {
          await db.execute("UPDATE tbl_orders SET order_status='ready' WHERE order_id=?", [order.order_id]);
          // A pick-up sale waits at the shop instead. Sales from before the
          // fulfilment column existed (NULL) keep going to delivery as they did.
          if (order.fulfillment !== "pickup" &&
              !(await db.query("SELECT 1 FROM tbl_deliveries WHERE order_id=?", [order.order_id], true))) {
            await db.execute("INSERT INTO tbl_deliveries (order_id, delivery_status) VALUES (?,'queued')", [
              order.order_id,
            ]);
          }
        }
      }
      await db.audit(req.user.user_id, `Completed fabrication #${fid}`, "tbl_fabrication_logs", clientIp(req));
    } else if (action === "pause") {
      await db.execute(
        "UPDATE tbl_fabrication_logs SET production_status='paused', paused_at=NOW() " +
          "WHERE fab_log_id=? AND production_status='in_progress'", [fid]);
      await db.audit(req.user.user_id, `Paused fabrication job #${fid}`, "tbl_fabrication_logs", clientIp(req));
    } else if (action === "resume") {
      await db.execute(
        "UPDATE tbl_fabrication_logs SET production_status='in_progress', paused_at=NULL, employee_id=? " +
          "WHERE fab_log_id=? AND production_status IN ('paused','qa_failed')",
        [req.user.user_id, fid]);
      await db.audit(req.user.user_id, `Resumed fabrication job #${fid}`, "tbl_fabrication_logs", clientIp(req));
    } else if (action === "send_qa") {
      await db.execute(
        "UPDATE tbl_fabrication_logs SET production_status='for_qa', sent_to_qa_at=NOW() " +
          "WHERE fab_log_id=? AND production_status IN ('in_progress','paused')", [fid]);
      await db.audit(req.user.user_id, `Sent job #${fid} to QA`, "tbl_fabrication_logs", clientIp(req));
    } else if (action === "qa_fail") {
      const reason = String(b.reason || "").trim();
      if (!reason) return res.status(400).json({ error: "A reason is required when QA fails." });
      await db.execute(
        "UPDATE tbl_fabrication_logs SET production_status='qa_failed', qa_failed_reason=?, " +
          "qa_by=?, qa_at=NOW() WHERE fab_log_id=?",
        [reason.slice(0, 500), req.user.user_id, fid]);
      await db.audit(req.user.user_id, `QA failed job #${fid}: ${reason.slice(0, 80)}`,
                     "tbl_fabrication_logs", clientIp(req));
    } else {
      return res.status(400).json({
        error: "action must be one of: start, pause, resume, send_qa, qa_fail, complete",
      });
    }
    res.json({ ok: true });
  })
);

// ===========================================================================
//  DELIVERY PERSONNEL
// ===========================================================================
app.get(
  "/api/delivery/queue",
  auth.requireRole("Delivery Personnel", "Administrator"),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT d.delivery_id, d.delivery_status, d.dispatch_time, d.delivery_time, " +
        "       o.order_id, o.order_reference, o.delivery_address, o.latitude, o.longitude, " +
        "       o.total_amount, u.full_name AS customer_name, u.phone AS customer_phone " +
        "FROM tbl_deliveries d JOIN tbl_orders o ON o.order_id = d.order_id " +
        "JOIN tbl_users u ON u.user_id = o.customer_id " +
        "WHERE d.delivery_status IN ('queued','dispatched','arrived') " +
        "ORDER BY d.delivery_id"
    );
    res.json({ deliveries: rows });
  })
);

app.post(
  "/api/delivery/:did/status",
  auth.requireRole("Delivery Personnel", "Administrator"),
  h(async (req, res) => {
    const did = parseInt(req.params.did, 10);
    const b = req.body || {};
    const status = b.status; // dispatched | arrived | delivered | failed
    const valid = new Set(["dispatched", "arrived", "delivered", "failed"]);
    if (!valid.has(status)) {
      return res.status(400).json({ error: `status must be one of ${JSON.stringify([...valid].sort())}` });
    }

    const sets = ["delivery_status=?", "driver_id=?"];
    const params = [status, req.user.user_id];
    if (status === "dispatched") sets.push("dispatch_time=NOW()");
    if (status === "delivered" || status === "failed") sets.push("delivery_time=NOW()");
    params.push(did);
    await db.execute(`UPDATE tbl_deliveries SET ${sets.join(", ")} WHERE delivery_id=?`, params);

    const order = await db.query("SELECT order_id FROM tbl_deliveries WHERE delivery_id=?", [did], true);
    if (order) {
      if (status === "dispatched") {
        await db.execute("UPDATE tbl_orders SET order_status='dispatched' WHERE order_id=?", [order.order_id]);
      } else if (status === "delivered") {
        await db.execute("UPDATE tbl_orders SET order_status='delivered' WHERE order_id=?", [order.order_id]);
      }
    }
    await db.audit(req.user.user_id, `Delivery #${did} -> ${status}`, "tbl_deliveries", clientIp(req));
    res.json({ ok: true });
  })
);

app.post(
  "/api/delivery/:did/pod",
  auth.requireRole("Delivery Personnel", "Administrator"),
  upload.single("photo"),
  h(async (req, res) => {
    // Proof of delivery: a captured photo (multipart) + a signature data-URL.
    const did = parseInt(req.params.did, 10);
    const signature = req.body.signature; // data:image/png;base64,...
    let imagePath = null;   // stored in tbl_uploads, and on disk when possible
    if (req.file) {
      const safe = `pod_${did}_${Math.floor(Date.now() / 1000)}.jpg`;
      const dest = path.join(UPLOAD_DIR, safe);
      imagePath = await req.app.locals.saveUpload(req.file, safe, req.user.user_id);
    }
    await db.execute(
      "UPDATE tbl_deliveries SET proof_of_delivery_image=?, digital_signature_data=?, " +
        "delivery_status='delivered', delivery_time=NOW(), driver_id=? WHERE delivery_id=?",
      [imagePath, signature, req.user.user_id, did]
    );
    const order = await db.query("SELECT order_id FROM tbl_deliveries WHERE delivery_id=?", [did], true);
    if (order) {
      await db.execute("UPDATE tbl_orders SET order_status='delivered' WHERE order_id=?", [order.order_id]);
    }
    await db.audit(req.user.user_id, `Logged POD for delivery #${did}`, "tbl_deliveries", clientIp(req));
    res.json({ ok: true, proof_of_delivery_image: imagePath });
  })
);

// ===========================================================================
//  STATIC FRONTEND
// ===========================================================================
//
//  The storefront lives in the same folder as the server code, so the static
//  handler is pointed at the project root. That would also hand out the SQL
//  dumps and the backend source to anyone who guessed the URL — the database
//  export alone contains every password hash. Everything server-side is denied
//  here, before either static path can reach it.
// ---------------------------------------------------------------------------
const PRIVATE_PREFIXES = ["database", "backend", "node_modules", ".git", ".vscode"];
const PRIVATE_FILES = [".env", ".env.example", "package.json", "package-lock.json"];

function isPrivatePath(urlPath) {
  // strip the leading slash, ignore any query string, normalise separators
  const clean = decodeURIComponent(String(urlPath).split("?")[0])
    .replace(/^\/+/, "")
    .replace(/\\/g, "/")
    .toLowerCase();
  if (!clean) return false;
  const first = clean.split("/")[0];
  if (PRIVATE_PREFIXES.includes(first)) return true;
  const base = clean.split("/").pop();
  if (PRIVATE_FILES.includes(base)) return true;
  // never serve a raw SQL dump from anywhere
  if (base.endsWith(".sql")) return true;
  return false;
}

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  if (isPrivatePath(req.path)) return res.status(404).json({ error: "Not found" });
  next();
});

app.get("/", (req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

app.use("/uploads", express.static(UPLOAD_DIR, { fallthrough: true }));
/**
 * Any upload the disk does not have is served from MySQL. After a redeploy on
 * a host with a throwaway filesystem, this is every one of them.
 */
app.get(
  "/uploads/:name",
  h(async (req, res) => {
    const name = String(req.params.name || "");
    if (!/^[A-Za-z0-9._-]{1,160}$/.test(name)) return res.status(404).json({ error: "Not found" });
    const row = await db.query(
      "SELECT mime_type, content FROM tbl_uploads WHERE filename=?", [name], true);
    if (!row) return res.status(404).json({ error: "Not found" });
    res.setHeader("Content-Type", row.mime_type || "application/octet-stream");
    // The name carries a timestamp, so a stored picture never changes.
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
    res.send(row.content);
  })
);
app.use(express.static(FRONTEND_DIR));

app.get(/^\/(?!api\/).*/, (req, res) => {
  const filename = req.path.replace(/^\//, "");
  if (isPrivatePath(req.path)) return res.status(404).json({ error: "Not found" });
  const full = path.join(FRONTEND_DIR, filename);
  // keep the resolved path inside the project folder (blocks ../ traversal)
  if (!path.resolve(full).startsWith(path.resolve(FRONTEND_DIR))) {
    return res.status(404).json({ error: "Not found" });
  }
  if (fs.existsSync(full) && fs.statSync(full).isFile()) {
    return res.sendFile(full);
  }
  res.status(404).json({ error: "Not found" });
});

app.use("/api", (req, res) => {
  res.status(404).json({ error: "Unknown API endpoint" });
});

// ===========================================================================
//  ERROR HANDLING  (any MySQL problem -> clear JSON)
// ===========================================================================
app.use((err, req, res, next) => {
  if (err && (err.code || "").toString().startsWith("ER_")) {
    return res.status(503).json({
      error:
        "Database unavailable. Start MySQL in the XAMPP Control Panel and " +
        "import database/schema.sql via phpMyAdmin, then check backend/.env.",
      detail: String(err.message || err),
    });
  }
  if (err && (err.errno || err.sqlState)) {
    return res.status(503).json({
      error:
        "Database unavailable. Start MySQL in the XAMPP Control Panel and " +
        "import database/schema.sql via phpMyAdmin, then check backend/.env.",
      detail: String(err.message || err),
    });
  }
  console.error(err);
  res.status(500).json({ error: "Internal server error", detail: String((err && err.message) || err) });
});

// ===========================================================================
app.listen(config.PORT, "0.0.0.0", () => {
  console.log("=".repeat(64));
  console.log("  Galaxy Trading backend");
  const base = process.env.PUBLIC_URL || `http://localhost:${config.PORT}`;
  console.log(`  Storefront : ${base}/`);
  console.log(`  Staff portal: ${base}/staff/portal.html`);
  console.log(`  Uploads   : ${UPLOAD_DIR}`);
  console.log(`  DB: ${config.DB_USER}@${config.DB_HOST}:${config.DB_PORT}/${config.DB_NAME}`);
  console.log("=".repeat(64));
});
