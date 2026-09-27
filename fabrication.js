/**
 * fabrication.js — the shop-floor workflow: assignment, order visibility,
 * damage reports, and the hand-off back to Sales and on to Delivery.
 *
 * WHY THIS EXISTS
 *   Storefront orders were written to tbl_online_orders and stopped there —
 *   nothing on the staff side ever read that table, so a customer's custom
 *   cut/bend order never reached the fabrication floor. And because there was
 *   no assignment step, every fabricator saw every queued job, so "give this
 *   one to Nheil" could not be expressed at all.
 *
 *   A fabrication log now hangs off EITHER a walk-in custom job OR a storefront
 *   order line. Both normalise to the same shape below, so the panel shows one
 *   queue and one set of buttons regardless of where the order came from.
 *
 * Mounted by app.js. Run database/migration_fabrication_workflow.sql first.
 */
const express = require("express");
const path = require("path");
const fs = require("fs");
const config = require("./config");
const multer = require("multer");

const auth = require("./auth");
const db = require("./db");

const router = express.Router();

const FRONTEND_DIR = path.resolve(__dirname, "..");
// Same folder app.js uses, so UPLOAD_DIR in .env moves both.
const UPLOAD_DIR = config.UPLOAD_DIR ? path.resolve(config.UPLOAD_DIR) : path.join(FRONTEND_DIR, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Damage photos: images only, 5MB, and the stored name is generated here so a
// crafted upload filename can never decide where the file lands.
const damageUploadRaw = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ok = ["image/jpeg", "image/jpg", "image/png"].includes(file.mimetype);
    cb(ok ? null : new Error("Only JPG, JPEG and PNG photos are allowed."), ok);
  },
}).single("photo");

/**
 * A rejected upload is the caller's mistake, not a server fault: turn multer's
 * error into a 400 with the reason, rather than letting it surface as a 500.
 */
const damageUpload = (req, res, next) =>
  damageUploadRaw(req, res, (err) => {
    if (!err) return next();
    const tooBig = err.code === "LIMIT_FILE_SIZE";
    return res.status(400).json({
      error: tooBig ? "That photo is larger than 5MB." : err.message || "That photo was rejected.",
    });
  });

// Both spellings exist in the wild: role 4 was renamed Employee -> Fabrication
// partway through, and accounts of both names are still in tbl_roles.
const FLOOR = ["Employee", "Fabrication", "Administrator"];
const SALES = ["Sales Manager", "Administrator"];

const h = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const clientIp = (req) =>
  (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress || "";

// ---------------------------------------------------------------------------
//  Reading jobs
// ---------------------------------------------------------------------------
//
//  One query, two possible parents. The walk-in chain is
//  custom_jobs -> order_items -> orders; the storefront chain is
//  online_order_items -> online_orders. Every job has exactly one of them, so
//  the unused side comes back NULL and normaliseJob() picks the right column.
//
const JOB_SELECT =
  "SELECT f.fab_log_id, f.production_status, f.scrap_waste_generated, f.started_at, " +
  "       f.completion_timestamp, f.paused_at, f.sent_to_qa_at, f.qa_checklist, " +
  "       f.qa_failed_reason, f.fabrication_notes, f.material_consumed, f.scrap_reason, " +
  "       f.custom_job_id, f.online_order_id, f.online_item_id, " +
  "       f.assigned_to, f.assigned_at, f.helper_1, f.helper_2, " +
  "       asg.full_name AS assigned_name, asg.username AS assigned_username, " +
  "       h1.full_name AS helper_1_name, h2.full_name AS helper_2_name, " +
  "       ab.full_name  AS assigned_by_name, " +
  "       emp.full_name AS worked_by, " +
  // --- walk-in side ---
  "       cj.cutting_length_meters, cj.number_of_cuts, cj.bending_angle_degrees, " +
  "       cj.number_of_bends, cj.design_file_path, cj.instructions AS cj_instructions, " +
  "       o.order_id AS legacy_order_id, o.order_reference AS legacy_ref, " +
  "       o.delivery_address AS legacy_address, o.notes AS legacy_notes, " +
  "       lu.full_name AS legacy_customer, lu.phone AS legacy_phone, " +
  "       oi.quantity AS legacy_qty, " +
  "       COALESCE(oi.item_description, p.product_name) AS legacy_item, " +
  "       m.material_name, m.unit_of_measure, m.stock_quantity AS material_stock, " +
  "       bom.quantity_required, " +
  // --- storefront side ---
  "       oo.order_ref AS online_ref, oo.customer_name AS online_customer, " +
  "       oo.address AS online_address, oo.fulfillment, oo.status AS online_status, " +
  "       oo.total AS online_total, oo.ordered_at, " +
  "       cu.phone AS online_phone, " +
  "       ooi.item_name, ooi.item_size, ooi.quantity AS online_qty, ooi.unit_price, " +
  "       ooi.image AS online_image, ooi.is_custom, ooi.custom_photo, " +
  "       ooi.cuts, ooi.bends, ooi.custom_instructions " +
  "FROM tbl_fabrication_logs f " +
  "LEFT JOIN tbl_custom_jobs cj       ON cj.custom_job_id = f.custom_job_id " +
  "LEFT JOIN tbl_order_items oi       ON oi.order_item_id = cj.order_item_id " +
  "LEFT JOIN tbl_orders o             ON o.order_id = oi.order_id " +
  "LEFT JOIN tbl_users lu             ON lu.user_id = o.customer_id " +
  "LEFT JOIN tbl_products p           ON p.product_id = oi.product_id " +
  "LEFT JOIN tbl_bill_of_materials bom ON bom.product_id = oi.product_id " +
  "LEFT JOIN tbl_raw_materials m      ON m.material_id = bom.material_id " +
  "LEFT JOIN tbl_online_order_items ooi ON ooi.item_id = f.online_item_id " +
  "LEFT JOIN tbl_online_orders oo     ON oo.online_order_id = f.online_order_id " +
  "LEFT JOIN tbl_users cu             ON cu.user_id = oo.user_id " +
  "LEFT JOIN tbl_users asg            ON asg.user_id = f.assigned_to " +
  "LEFT JOIN tbl_users h1             ON h1.user_id = f.helper_1 " +
  "LEFT JOIN tbl_users h2             ON h2.user_id = f.helper_2 " +
  "LEFT JOIN tbl_users ab             ON ab.user_id = f.assigned_by " +
  "LEFT JOIN tbl_users emp            ON emp.user_id = f.employee_id ";

const num = (v) => (v === null || v === undefined || v === "" ? null : Number(v));

/** Collapse the two parent chains into the single shape the panel renders. */
function normaliseJob(r) {
  const storefront = r.online_item_id !== null;

  const qty = storefront ? r.online_qty : r.legacy_qty;
  const perUnit = num(r.quantity_required);
  const required = perUnit === null ? null : perUnit * (Number(qty) || 1);
  const stock = num(r.material_stock);

  return {
    fab_log_id: r.fab_log_id,
    source: storefront ? "storefront" : "walk-in",
    production_status: r.production_status,

    // what the customer ordered
    order_ref: storefront ? r.online_ref : r.legacy_ref,
    online_order_id: r.online_order_id,
    legacy_order_id: r.legacy_order_id,
    customer_name: storefront ? r.online_customer : r.legacy_customer,
    customer_phone: storefront ? r.online_phone : r.legacy_phone,
    delivery_address: storefront ? r.online_address : r.legacy_address,
    fulfillment: r.fulfillment || null,
    order_total: num(r.online_total),
    ordered_at: r.ordered_at || null,
    order_status: r.online_status || null,

    item_name: storefront ? r.item_name : r.legacy_item,
    item_size: storefront ? r.item_size : null,
    quantity: Number(qty) || 0,
    unit_price: num(r.unit_price),
    item_image: storefront ? r.online_image : null,

    // the customisation the customer asked for
    is_custom: storefront ? !!r.is_custom : true,
    cuts: storefront ? Number(r.cuts) || 0 : Number(r.number_of_cuts) || 0,
    bends: storefront ? Number(r.bends) || 0 : Number(r.number_of_bends) || 0,
    cut_length_m: storefront ? null : num(r.cutting_length_meters),
    bend_angle_deg: storefront ? null : num(r.bending_angle_degrees),
    custom_instructions: storefront ? r.custom_instructions : (r.cj_instructions || r.legacy_notes),
    // the reference picture the customer uploaded at checkout
    custom_photo: storefront ? r.custom_photo : r.design_file_path,

    // who it belongs to
    assigned_to: r.assigned_to,
    assigned_name: r.assigned_name,
    assigned_username: r.assigned_username,
    assigned_by_name: r.assigned_by_name,
    assigned_at: r.assigned_at,
    // The main fabricator owns the job; helpers assist with it.
    helper_1: r.helper_1,
    helper_1_name: r.helper_1_name,
    helper_2: r.helper_2,
    helper_2_name: r.helper_2_name,
    worked_by: r.worked_by,

    // material, where a bill of materials exists to say
    material_name: r.material_name || null,
    unit_of_measure: r.unit_of_measure || null,
    material_stock: stock,
    material_required: required,
    material_sufficient: r.material_name ? stock >= required : null,
    material_remaining: r.material_name ? Math.round((stock - required) * 100) / 100 : null,

    // progress
    started_at: r.started_at,
    paused_at: r.paused_at,
    sent_to_qa_at: r.sent_to_qa_at,
    completion_timestamp: r.completion_timestamp,
    scrap_waste_generated: num(r.scrap_waste_generated),
    fabrication_notes: r.fabrication_notes,
    qa_checklist: r.qa_checklist,
    qa_failed_reason: r.qa_failed_reason,
  };
}

const OPEN_STATUSES = "('queued','in_progress','paused','for_qa','qa_failed')";

/**
 * What this user is on this job: "main" (it is theirs, or they are an
 * Administrator), "helper" (assisting) or "other" (anyone else on the floor,
 * who keeps the read access the panel always had).
 */
function jobRole(job, user) {
  if (user.role === "Administrator") return "main";
  if (job.assigned_to === user.user_id) return "main";
  if (job.helper_1 === user.user_id || job.helper_2 === user.user_id) return "helper";
  return "other";
}

/**
 * A helper is given the picture and the work to do, and nothing else: no
 * customer, no address, no prices, no order totals.
 */
function helperView(job) {
  return {
    fab_log_id: job.fab_log_id,
    source: job.source,
    production_status: job.production_status,
    order_ref: job.order_ref,
    item_name: job.item_name,
    item_size: job.item_size,
    quantity: job.quantity,
    is_custom: job.is_custom,
    cuts: job.cuts,
    bends: job.bends,
    cut_length_m: job.cut_length_m,
    bend_angle_deg: job.bend_angle_deg,
    custom_instructions: job.custom_instructions,
    // what the helper is here for
    custom_photo: job.custom_photo,
    item_image: job.item_image,
    material_name: job.material_name,
    unit_of_measure: job.unit_of_measure,
    material_required: job.material_required,
    // who to ask about it
    assigned_name: job.assigned_name,
    helper_1_name: job.helper_1_name,
    helper_2_name: job.helper_2_name,
    started_at: job.started_at,
    sent_to_qa_at: job.sent_to_qa_at,
    completion_timestamp: job.completion_timestamp,
    my_role: "helper",
  };
}

/**
 * The floor's queue.
 *   ?scope=mine  (default) only jobs assigned to me, plus anything unassigned
 *   ?scope=all              the whole floor, so a supervisor can look across
 */
router.get(
  "/api/fabrication/jobs",
  auth.requireRole(...FLOOR),
  h(async (req, res) => {
    const scope = req.query.scope === "all" ? "all" : "mine";
    const params = [];
    let where = `WHERE f.production_status IN ${OPEN_STATUSES} `;
    if (scope === "mine") {
      // Unassigned work stays visible so nothing is stranded when the Sales
      // Manager has not handed it out yet. Jobs someone is helping on show up
      // here as well, marked as such.
      where += "AND (f.assigned_to = ? OR f.helper_1 = ? OR f.helper_2 = ? OR f.assigned_to IS NULL) ";
      params.push(req.user.user_id, req.user.user_id, req.user.user_id);
    }
    const rows = await db.query(
      JOB_SELECT + where +
        "ORDER BY FIELD(f.production_status,'in_progress','paused','qa_failed','for_qa','queued'), " +
        "         f.assigned_at IS NULL, f.fab_log_id",
      params
    );
    const jobs = rows.map(normaliseJob).map((j) => {
      const role = jobRole(j, req.user);
      // In the list a helper sees only enough to recognise the job.
      return role === "helper" ? helperView(j) : Object.assign(j, { my_role: role });
    });

    // Tiles count the same scope the list shows, so the numbers agree with it.
    const mine = jobs.filter((j) => j.assigned_to === req.user.user_id);
    const summary = {
      assigned_to_me: mine.length,
      helping_with: jobs.filter((j) => j.my_role === "helper").length,
      unassigned: jobs.filter((j) => j.assigned_to === null).length,
      queued: jobs.filter((j) => j.production_status === "queued").length,
      in_progress: jobs.filter((j) => j.production_status === "in_progress").length,
      paused: jobs.filter((j) => j.production_status === "paused").length,
      for_qa: jobs.filter((j) => j.production_status === "for_qa").length,
      qa_failed: jobs.filter((j) => j.production_status === "qa_failed").length,
    };
    const done = await db.query(
      "SELECT COUNT(*) n FROM tbl_fabrication_logs " +
        "WHERE production_status='completed' AND DATE(completion_timestamp)=CURDATE() " +
        "AND (employee_id=? OR assigned_to=?)",
      [req.user.user_id, req.user.user_id],
      true
    );
    summary.completed_today = (done && done.n) || 0;

    res.json({ jobs, summary, scope });
  })
);

/** One job in full, for the order-detail view. */
router.get(
  "/api/fabrication/jobs/:fid",
  auth.requireRole(...FLOOR),
  h(async (req, res) => {
    const fid = parseInt(req.params.fid, 10);
    const row = await db.query(JOB_SELECT + "WHERE f.fab_log_id=?", [fid], true);
    if (!row) return res.status(404).json({ error: "Job not found" });
    const job = normaliseJob(row);
    const role = jobRole(job, req.user);

    // A helper gets the design and the work to do, not the customer's details.
    if (role === "helper") {
      return res.json({ job: helperView(job), items: [], damage: [], my_role: "helper" });
    }
    job.my_role = role;

    // Every line on the same customer order, so the floor sees the whole order
    // rather than just the piece in front of them.
    let siblings = [];
    if (job.online_order_id) {
      siblings = await db.query(
        "SELECT item_id, item_name, item_size, quantity, unit_price, is_custom, " +
          "       cuts, bends, custom_instructions, custom_photo " +
          "FROM tbl_online_order_items WHERE online_order_id=? ORDER BY item_id",
        [job.online_order_id]
      );
    } else if (job.legacy_order_id) {
      siblings = await db.query(
        "SELECT oi.order_item_id AS item_id, " +
          "       COALESCE(oi.item_description, p.product_name) AS item_name, " +
          "       NULL AS item_size, oi.quantity, oi.unit_price, " +
          "       (cj.custom_job_id IS NOT NULL) AS is_custom, " +
          "       cj.number_of_cuts AS cuts, cj.number_of_bends AS bends, " +
          "       cj.instructions AS custom_instructions " +
          "FROM tbl_order_items oi LEFT JOIN tbl_products p ON p.product_id=oi.product_id " +
          "LEFT JOIN tbl_custom_jobs cj ON cj.order_item_id=oi.order_item_id " +
          "WHERE oi.order_id=? ORDER BY oi.order_item_id",
        [job.legacy_order_id]
      );
    }

    const damage = await db.query(
      "SELECT d.damage_id, d.damage_type, d.item_name, d.description, d.severity, " +
        "       d.photo_path, d.status, d.sales_response, d.created_at, u.full_name AS reporter " +
        "FROM tbl_damage_reports d JOIN tbl_users u ON u.user_id=d.reported_by " +
        "WHERE d.fab_log_id=? ORDER BY d.damage_id DESC",
      [fid]
    );

    res.json({ job, items: siblings, damage, my_role: role });
  })
);

/** Finished and failed jobs — the floor's own history. */
router.get(
  "/api/fabrication/history",
  auth.requireRole(...FLOOR),
  h(async (req, res) => {
    const rows = await db.query(
      JOB_SELECT +
        "WHERE f.production_status IN ('completed','qa_failed') " +
        "ORDER BY COALESCE(f.completion_timestamp, f.started_at) DESC, f.fab_log_id DESC LIMIT 100",
      []
    );
    res.json({ history: rows.map(normaliseJob) });
  })
);

// ---------------------------------------------------------------------------
//  Damage reports
// ---------------------------------------------------------------------------

/**
 * Raise damage from the floor, with a photo.
 * multipart/form-data so the phone camera can post straight into it.
 */
router.post(
  "/api/fabrication/damage",
  auth.requireRole(...FLOOR),
  damageUpload,
  h(async (req, res) => {
    const b = req.body || {};
    const description = String(b.description || "").trim();
    if (!description) {
      return res.status(400).json({ error: "Describe what is damaged." });
    }

    const types = ["raw_material", "customization", "finished_item", "other"];
    const damageType = types.includes(b.damage_type) ? b.damage_type : "raw_material";
    const severities = ["minor", "major", "critical"];
    const severity = severities.includes(b.severity) ? b.severity : "minor";

    const fid = b.fab_log_id ? parseInt(b.fab_log_id, 10) : null;
    let onlineOrderId = null;
    if (fid) {
      const job = await db.query(
        "SELECT online_order_id FROM tbl_fabrication_logs WHERE fab_log_id=?", [fid], true);
      if (!job) return res.status(404).json({ error: "Job not found" });
      onlineOrderId = job.online_order_id;
    }

    // Generated filename — never the one the browser supplied.
    let photoPath = null;
    if (req.file) {
      const safe = `damage_${Date.now()}_${req.user.user_id}.jpg`;
      // Stored in the database (and on disk when it is writable), so the photo
      // outlives a redeploy on a host with a throwaway filesystem.
      photoPath = await req.app.locals.saveUpload(req.file, safe, req.user.user_id);
    }

    const damageId = await db.execute(
      "INSERT INTO tbl_damage_reports (fab_log_id, online_order_id, reported_by, damage_type, " +
        "item_name, description, severity, photo_path, quantity_affected) " +
        "VALUES (?,?,?,?,?,?,?,?,?)",
      [
        fid,
        onlineOrderId,
        req.user.user_id,
        damageType,
        String(b.item_name || "").slice(0, 160) || null,
        description.slice(0, 1000),
        severity,
        photoPath,
        b.quantity_affected ? Number(b.quantity_affected) : null,
      ]
    );

    await db.audit(
      req.user.user_id,
      `Reported ${severity} damage: ${description.slice(0, 60)}`,
      "tbl_damage_reports",
      clientIp(req)
    );
    res.json({ ok: true, damage_id: damageId, photo_path: photoPath });
  })
);

/** What this fabricator has reported. */
router.get(
  "/api/fabrication/damage",
  auth.requireRole(...FLOOR),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT d.*, u.full_name AS reporter, rv.full_name AS reviewer, " +
        "       COALESCE(oo.order_ref, o.order_reference) AS order_ref " +
        "FROM tbl_damage_reports d " +
        "JOIN tbl_users u ON u.user_id = d.reported_by " +
        "LEFT JOIN tbl_users rv ON rv.user_id = d.reviewed_by " +
        "LEFT JOIN tbl_online_orders oo ON oo.online_order_id = d.online_order_id " +
        "LEFT JOIN tbl_fabrication_logs f ON f.fab_log_id = d.fab_log_id " +
        "LEFT JOIN tbl_custom_jobs cj ON cj.custom_job_id = f.custom_job_id " +
        "LEFT JOIN tbl_order_items oi ON oi.order_item_id = cj.order_item_id " +
        "LEFT JOIN tbl_orders o ON o.order_id = oi.order_id " +
        "WHERE d.reported_by=? ORDER BY d.damage_id DESC LIMIT 100",
      [req.user.user_id]
    );
    res.json({ damage: rows });
  })
);

// ===========================================================================
//  SALES MANAGER SIDE
// ===========================================================================

/**
 * Read helper_1 / helper_2 out of a request body.
 *
 * Resolves to { h1, h2, names } or { error } — a helper has to be a real
 * fabrication employee, cannot be the main fabricator, and the same person
 * cannot fill both helper slots.
 */
async function readHelpers(body, assignTo) {
  const ids = [body && body.helper_1, body && body.helper_2]
    .map((v) => (v ? parseInt(v, 10) : null))
    .map((v) => (Number.isFinite(v) && v > 0 ? v : null));
  const names = [];
  const seen = [];
  for (const id of ids) {
    if (id === null) { seen.push(null); continue; }
    if (id === assignTo) {
      return { error: "A helper cannot also be the main fabrication staff for the same job." };
    }
    if (seen.includes(id)) {
      return { error: "The same person cannot be both helpers." };
    }
    const who = await db.query(
      "SELECT u.full_name FROM tbl_users u JOIN tbl_roles r ON r.role_id=u.role_id " +
        "WHERE u.user_id=? AND u.is_active=1 AND r.role_name IN ('Fabrication','Employee')",
      [id], true);
    if (!who) return { error: "A helper must be an active fabrication employee." };
    names.push(who.full_name);
    seen.push(id);
  }
  // Helper 2 without helper 1 is still one helper: keep them in order.
  const kept = seen.filter((v) => v !== null);
  return { h1: kept[0] || null, h2: kept[1] || null, names };
}

/** The fabricators a job can be handed to. */
router.get(
  "/api/sales/fabricators",
  auth.requireRole(...SALES),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT u.user_id, u.username, u.full_name, " +
        "  (SELECT COUNT(*) FROM tbl_fabrication_logs f " +
        `   WHERE f.assigned_to = u.user_id AND f.production_status IN ${OPEN_STATUSES}) AS open_jobs ` +
        "FROM tbl_users u JOIN tbl_roles r ON r.role_id = u.role_id " +
        "WHERE r.role_name IN ('Fabrication','Employee') ORDER BY u.full_name"
    );
    res.json({ fabricators: rows });
  })
);

// NOTE: the storefront order book is served by GET /api/online-orders in
// customers.js, which the sales page already used. A second endpoint here
// returning the same orders would drift out of step with it, so the
// fabrication fields were added to that one instead (orderOut in customers.js).

/**
 * Accept a storefront order and put it on the floor.
 *
 * Creates one fabrication job per order line and assigns them all to the
 * chosen fabricator. Re-running it on an order that already has jobs only
 * re-assigns them, so a mis-click cannot duplicate the work.
 */
router.post(
  "/api/sales/online-orders/:oid/release",
  auth.requireRole(...SALES),
  h(async (req, res) => {
    const oid = parseInt(req.params.oid, 10);
    const assignTo = req.body && req.body.assign_to ? parseInt(req.body.assign_to, 10) : null;
    const helpers = await readHelpers(req.body, assignTo);
    if (helpers.error) return res.status(400).json({ error: helpers.error });
    // Only custom lines need fabrication; a plain stock item does not.
    const customOnly = !(req.body && req.body.include_all);

    const order = await db.query(
      "SELECT online_order_id, order_ref, status FROM tbl_online_orders WHERE online_order_id=?",
      [oid], true);
    if (!order) return res.status(404).json({ error: "Order not found" });
    if (order.status === "declined" || order.status === "cancelled") {
      return res.status(400).json({ error: `This order is ${order.status} and cannot be released.` });
    }

    if (assignTo) {
      const who = await db.query(
        "SELECT u.user_id FROM tbl_users u JOIN tbl_roles r ON r.role_id=u.role_id " +
          "WHERE u.user_id=? AND r.role_name IN ('Fabrication','Employee')",
        [assignTo], true);
      if (!who) return res.status(400).json({ error: "That user is not a fabrication employee." });
    }

    let items = await db.query(
      "SELECT item_id, is_custom FROM tbl_online_order_items WHERE online_order_id=?", [oid]);
    if (customOnly && items.some((i) => i.is_custom)) {
      items = items.filter((i) => i.is_custom);
    }
    if (!items.length) return res.status(400).json({ error: "This order has no lines to fabricate." });

    let created = 0;
    let reassigned = 0;
    for (const it of items) {
      const existing = await db.query(
        "SELECT fab_log_id FROM tbl_fabrication_logs WHERE online_item_id=?", [it.item_id], true);
      if (existing) {
        await db.execute(
          "UPDATE tbl_fabrication_logs SET assigned_to=?, helper_1=?, helper_2=?, " +
            "assigned_by=?, assigned_at=NOW() WHERE fab_log_id=?",
          [assignTo, helpers.h1, helpers.h2, req.user.user_id, existing.fab_log_id]);
        reassigned++;
      } else {
        await db.execute(
          "INSERT INTO tbl_fabrication_logs (online_order_id, online_item_id, production_status, " +
            "assigned_to, helper_1, helper_2, assigned_by, assigned_at) VALUES (?,?,'queued',?,?,?,?,NOW())",
          [oid, it.item_id, assignTo, helpers.h1, helpers.h2, req.user.user_id]);
        created++;
      }
    }

    await db.execute(
      "UPDATE tbl_online_orders SET status='in_fabrication' WHERE online_order_id=?", [oid]);

    const name = assignTo
      ? (await db.query("SELECT full_name FROM tbl_users WHERE user_id=?", [assignTo], true) || {}).full_name
      : "the floor";
    await db.audit(
      req.user.user_id,
      `Released order ${order.order_ref} to ${name}` +
        (helpers.names.length ? ` with ${helpers.names.join(" and ")}` : "") +
        ` (${created} new, ${reassigned} re-assigned)`,
      "tbl_fabrication_logs",
      clientIp(req)
    );
    res.json({ ok: true, created, reassigned, assigned_to: assignTo,
               helper_1: helpers.h1, helper_2: helpers.h2, helper_names: helpers.names });
  })
);

/**
 * Hand a finished order to the delivery panel.
 * Only allowed once the floor has actually finished every job on it.
 */
router.post(
  "/api/sales/online-orders/:oid/to-delivery",
  auth.requireRole(...SALES),
  h(async (req, res) => {
    const oid = parseInt(req.params.oid, 10);
    const order = await db.query(
      "SELECT online_order_id, order_ref, status FROM tbl_online_orders WHERE online_order_id=?",
      [oid], true);
    if (!order) return res.status(404).json({ error: "Order not found" });

    const outstanding = await db.query(
      "SELECT COUNT(*) n FROM tbl_fabrication_logs " +
        "WHERE online_order_id=? AND production_status <> 'completed'",
      [oid], true);
    if (outstanding && outstanding.n > 0) {
      return res.status(400).json({
        error: `${outstanding.n} job(s) on this order are not finished yet.`,
      });
    }

    await db.execute(
      "UPDATE tbl_online_orders SET status='out_for_delivery', released_to_delivery_at=NOW() " +
        "WHERE online_order_id=?", [oid]);
    await db.audit(req.user.user_id, `Released ${order.order_ref} to delivery`,
                   "tbl_online_orders", clientIp(req));
    res.json({ ok: true });
  })
);

/** Every damage report, newest first — the Sales Manager's inbox. */
router.get(
  "/api/sales/damage",
  auth.requireRole(...SALES),
  h(async (req, res) => {
    const params = [];
    let sql =
      "SELECT d.*, u.full_name AS reporter, u.username AS reporter_username, " +
      "       rv.full_name AS reviewer, oo.order_ref, oo.customer_name, " +
      "       f.production_status " +
      "FROM tbl_damage_reports d " +
      "JOIN tbl_users u ON u.user_id = d.reported_by " +
      "LEFT JOIN tbl_users rv ON rv.user_id = d.reviewed_by " +
      "LEFT JOIN tbl_online_orders oo ON oo.online_order_id = d.online_order_id " +
      "LEFT JOIN tbl_fabrication_logs f ON f.fab_log_id = d.fab_log_id ";
    if (req.query.status) {
      sql += "WHERE d.status = ? ";
      params.push(req.query.status);
    }
    sql += "ORDER BY FIELD(d.severity,'critical','major','minor'), d.damage_id DESC LIMIT 200";
    const rows = await db.query(sql, params);
    const open = rows.filter((r) => r.status === "open").length;
    res.json({ damage: rows, open_count: open });
  })
);

/** Acknowledge or resolve a damage report, with a reply back to the floor. */
router.post(
  "/api/sales/damage/:id/review",
  auth.requireRole(...SALES),
  h(async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const b = req.body || {};
    const status = ["acknowledged", "resolved"].includes(b.status) ? b.status : null;
    if (!status) {
      return res.status(400).json({ error: "status must be 'acknowledged' or 'resolved'" });
    }
    await db.execute(
      "UPDATE tbl_damage_reports SET status=?, sales_response=?, reviewed_by=?, reviewed_at=NOW() " +
        "WHERE damage_id=?",
      [status, String(b.response || "").slice(0, 1000) || null, req.user.user_id, id]);
    await db.audit(req.user.user_id, `Marked damage report #${id} ${status}`,
                   "tbl_damage_reports", clientIp(req));
    res.json({ ok: true });
  })
);

// ===========================================================================
//  DELIVERY SIDE
// ===========================================================================
//
//  tbl_deliveries.order_id is foreign-keyed to the walk-in tbl_orders, so a
//  storefront order cannot be put in it without restructuring that table.
//  These two routes give the delivery panel the storefront orders as a second
//  list instead, leaving the existing walk-in delivery flow alone.
//
const DELIVERY = ["Delivery Personnel", "Administrator"];

router.get(
  "/api/delivery/online-queue",
  auth.requireRole(...DELIVERY),
  h(async (req, res) => {
    const rows = await db.query(
      "SELECT oo.online_order_id, oo.order_ref, oo.customer_name, oo.address, oo.status, " +
        "       oo.total, oo.fulfillment, oo.payment_method, oo.payment_status, " +
        "       oo.released_to_delivery_at, u.phone AS customer_phone, " +
        "       (SELECT COUNT(*) FROM tbl_online_order_items i " +
        "         WHERE i.online_order_id = oo.online_order_id) AS item_count " +
        "FROM tbl_online_orders oo LEFT JOIN tbl_users u ON u.user_id = oo.user_id " +
        "WHERE oo.status IN ('out_for_delivery','ready_for_delivery') " +
        "ORDER BY oo.released_to_delivery_at IS NULL, oo.released_to_delivery_at, oo.online_order_id"
    );
    res.json({ deliveries: rows });
  })
);

router.post(
  "/api/delivery/online/:oid/status",
  auth.requireRole(...DELIVERY),
  h(async (req, res) => {
    const oid = parseInt(req.params.oid, 10);
    const status = (req.body || {}).status;
    if (!["out_for_delivery", "delivered"].includes(status)) {
      return res.status(400).json({ error: "status must be 'out_for_delivery' or 'delivered'" });
    }
    await db.execute("UPDATE tbl_online_orders SET status=? WHERE online_order_id=?", [status, oid]);
    await db.audit(req.user.user_id, `Storefront order #${oid} -> ${status}`,
                   "tbl_online_orders", clientIp(req));
    res.json({ ok: true });
  })
);

module.exports = router;
module.exports.readHelpers = readHelpers;
