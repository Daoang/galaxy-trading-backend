/**
 * stock.js — drawing the shelf, and the Item History that records it.
 *
 * Every sale goes through here, so there is one place that decides what the
 * shelf does and one place that writes the history the Inventory Manager
 * reads:
 *
 *   walk-in sale          -> draw() when the counter completes the sale
 *   online order accepted -> draw() when the Sales Manager accepts it
 *   online order declined -> giveBack(), but only if it had been accepted
 *
 * Each function takes a `run` — anything with mysql2's query signature, so a
 * route can pass its own transaction connection (conn.query) and the rows land
 * or roll back with everything else.
 */

/** A conditional UPDATE: it only matches while enough is left on the shelf. */
async function takeFromShelf(run, where, params, qty) {
  const [res] = await run(
    "UPDATE tbl_products SET stock_quantity = stock_quantity - ? " +
      "WHERE " + where + " AND stock_quantity >= ?",
    [qty, ...params, qty]
  );
  return res.affectedRows > 0;
}

/** One line of the Item History. */
async function record(run, m) {
  await run(
    "INSERT INTO tbl_stock_movements " +
      "(item_type, item_id, item_name, movement, source, quantity, stock_before, stock_after, " +
      " reference, note, performed_by) VALUES ('product',?,?,?,?,?,?,?,?,?,?)",
    [
      m.productId || null,
      String(m.name || "Item").slice(0, 160),
      m.movement,                                   // 'out' when sold, 'in' when returned
      String(m.source || "").slice(0, 20),          // 'online' | 'walkin' | 'return'
      Math.abs(Math.trunc(m.qty)),
      m.before == null ? null : Math.trunc(m.before),
      Math.trunc(m.after),
      m.reference ? String(m.reference).slice(0, 80) : null,
      m.note ? String(m.note).slice(0, 255) : null,
      m.by ? String(m.by).slice(0, 80) : null,
    ]
  );
}

/**
 * Take `qty` of one product off the shelf and write the history line.
 *
 * The product is named either by its product_id (the counter knows it) or by
 * its sku, which is the storefront's own catalog id.
 *
 * Resolves to { ok:true, before, after } or, when the shelf cannot cover it,
 * { ok:false, left, name } so the caller can say so in its own words.
 */
async function draw(run, opts) {
  const qty = Math.max(1, Math.trunc(opts.qty || 0));
  const byId = opts.productId != null;
  const where = byId ? "product_id=?" : "sku=? AND status='active'";
  const params = [byId ? opts.productId : String(opts.sku || "")];

  const [rows] = await run(
    "SELECT product_id, product_name, stock_quantity FROM tbl_products WHERE " + where,
    params
  );
  const row = rows && rows[0];
  if (!row) return { ok: false, missing: true, left: 0, name: opts.name || "" };

  if (!(await takeFromShelf(run, where, params, qty))) {
    return { ok: false, left: Number(row.stock_quantity) || 0, name: row.product_name };
  }
  const before = Number(row.stock_quantity) || 0;
  const after = before - qty;
  await record(run, {
    productId: row.product_id, name: row.product_name, movement: "out",
    source: opts.source, qty, before, after,
    reference: opts.reference, note: opts.note, by: opts.by,
  });
  return { ok: true, before, after, productId: row.product_id, name: row.product_name };
}

/** Put stock back — a declined order, or one taken off an accepted order. */
async function giveBack(run, opts) {
  const qty = Math.max(1, Math.trunc(opts.qty || 0));
  const byId = opts.productId != null;
  const where = byId ? "product_id=?" : "sku=?";
  const params = [byId ? opts.productId : String(opts.sku || "")];

  const [rows] = await run(
    "SELECT product_id, product_name, stock_quantity FROM tbl_products WHERE " + where,
    params
  );
  const row = rows && rows[0];
  if (!row) return { ok: false };

  await run("UPDATE tbl_products SET stock_quantity = stock_quantity + ? WHERE " + where,
            [qty, ...params]);
  const before = Number(row.stock_quantity) || 0;
  await record(run, {
    productId: row.product_id, name: row.product_name, movement: "in",
    source: opts.source || "return", qty, before, after: before + qty,
    reference: opts.reference, note: opts.note, by: opts.by,
  });
  return { ok: true, before, after: before + qty };
}

module.exports = { draw, giveBack, record };
