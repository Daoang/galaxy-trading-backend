// Galaxy Trading product catalog
const PHP = (n) => "₱" + Number(n).toLocaleString("en-PH", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

// Products that can be cut or bent to order. ONLY these may be customized:
// the checkout shows the customization option for them alone, the Sales
// Manager's POS only offers them for a custom cut/bend job, and the server
// (backend/customers.js, backend/app.js) refuses customization of anything else.
// To make another product customizable, add its exact name here.
// ("Stainless Tubo (Pipe)" is the catalog's name for Stainless Tube (Pipe).)
const CUSTOMIZABLE_NAMES = [
  "Stainless Tubo (Pipe)",
  "Stainless Sheet (2B Finish)",
  "Tubular Steel",
  "Long Span Roofing",
  "Checkered Plate",
  "Stainless Mirror Finish Sheet",
  "Stainless Hairline Finish Sheet",
  "Color Sheet",
  "Angle Bar",
  "Stainless Shafting",
];

// `extra` accepts optional attributes that not every product needs:
//   color  — variant color (e.g. roofing colors). Does not affect price.
//   boxQty — pieces per box, shown as a small note when unit is "box".
const make = (name, category, size, price, image, unit = "pc", sale = false, extra = {}) => ({
  id: slug(name) + "-" + slug(size) + (extra.color ? "-" + slug(extra.color) : ""),
  name, category, size, price, image: "images/" + image, unit, sale,
  color: extra.color || null,
  boxQty: extra.boxQty || null,
  customizable: CUSTOMIZABLE_NAMES.includes(name),
});

// Long Span Roofing — one product photo, multiple lengths × colors.
// Color does not change the price; price is driven by length only.
const ROOFING_SIZES = [
  { size: "8ft", price: 720, sale: true },
  { size: "10ft", price: 900 },
  { size: "20ft", price: 1800 },
  { size: "up to 28ft", price: 2520 },
];
const ROOFING_COLORS = ["Blue", "Green", "Brown", "Red", "Beige", "Grey"];
const ROOFING_VARIANTS = ROOFING_SIZES.flatMap(({ size, price, sale }) =>
  ROOFING_COLORS.map((color) =>
    make("Long Span Roofing", "Roofing Material", size, price, "cat-roofing.jpg", "length", sale || false, { color })
  )
);

const PRODUCTS = [
  make("Stainless Tubo (Pipe)", "Stainless Steel Pipe", "1/2\"", 480, "cat-pipe.jpg", "length", true),
  make("Stainless Tubo (Pipe)", "Stainless Steel Pipe", "1\"", 720, "cat-pipe.jpg", "length"),
  make("Stainless Tubo (Pipe)", "Stainless Steel Pipe", "1 1/4\"", 980, "cat-pipe.jpg", "length"),
  make("Stainless Tubo (Pipe)", "Stainless Steel Pipe", "2\"", 1450, "cat-pipe.jpg", "length"),
  make("Stainless Tubo (Pipe)", "Stainless Steel Pipe", "2 1/2\"", 1850, "cat-pipe.jpg", "length"),
  make("Stainless Tubo (Pipe)", "Stainless Steel Pipe", "3\"", 2400, "cat-pipe.jpg", "length"),

  make("Stainless Sheet (2B Finish)", "Stainless Steel Sheet", "4x8 ft", 3200, "cat-sheet.jpg", "sheet"),
  make("Stainless Sheet (2B Finish)", "Stainless Steel Sheet", "0.4mm", 1850, "cat-sheet.jpg", "sheet"),
  make("Stainless Sheet (2B Finish)", "Stainless Steel Sheet", "0.5mm", 2200, "cat-sheet.jpg", "sheet"),
  make("Stainless Sheet (2B Finish)", "Stainless Steel Sheet", "0.6mm", 2650, "cat-sheet.jpg", "sheet"),
  make("Stainless Sheet (2B Finish)", "Stainless Steel Sheet", "0.9mm", 3950, "cat-sheet.jpg", "sheet"),

  make("Drill Bit", "Drill Tools", "1/8\"", 65, "cat-drill.jpg", "pc", true),
  make("Drill Bit", "Drill Tools", "5/32\"", 80, "cat-drill.jpg"),
  make("Drill Bit", "Drill Tools", "3/16\"", 95, "cat-drill.jpg"),
  make("Drill Bit", "Drill Tools", "1/4\"", 120, "cat-drill.jpg"),

  make("Cutting Off Wheel", "Cutting Tool", "14\"", 145, "cat-cutting.jpg"),
  make("Cutting Off Wheel", "Cutting Tool", "4\" (100mm)", 145, "cat-cutting.jpg", "box", false, { boxQty: 25 }),
  make("Cutting Off Wheel", "Cutting Tool", "4.5\" (115mm)", 145, "cat-cutting.jpg", "box", false, { boxQty: 25 }),
  make("Cutting Off Wheel", "Cutting Tool", "7\" (180mm)", 145, "cat-cutting.jpg", "box", false, { boxQty: 25 }),
  make("Cutting Disk", "Cutting Tool", "4\"", 45, "cat-cutting.jpg", "box", true, { boxQty: 25 }),

  make("Welding Rod", "Welding Supply", "2.0mm", 280, "cat-welding.jpg", "box", false, { boxQty: 120 }),
  make("Welding Rod", "Welding Supply", "2.5mm", 320, "cat-welding.jpg", "box", false, { boxQty: 110 }),

  make("Grinding Stone", "Grinding Tool", "6-Inch", 95, "cat-grinding.jpg", "box", false, { boxQty: 10 }),
  make("Nylon Flap Disk", "Polishing / Grinding", "4.5-Inch", 110, "cat-grinding.jpg", "box", false, { boxQty: 10 }),
  make("Buffing Cotton Wheel", "Polishing Tool", "Standard", 180, "cat-polishing.jpg"),

  make("Tubular Steel", "Structural Steel", "1x1", 520, "cat-tubular.jpg", "length"),
  make("Tubular Steel", "Structural Steel", "1x2", 780, "cat-tubular.jpg", "length"),
  make("Tubular Steel", "Structural Steel", "2x3", 1450, "cat-tubular.jpg", "length"),
  make("Tubular Steel", "Structural Steel", "2x4", 1850, "cat-tubular.jpg", "length"),
  make("Tubular Steel", "Structural Steel", "1 1/2\"", 920, "cat-tubular.jpg", "length"),
  make("Tubular Steel", "Structural Steel", "1\"", 680, "cat-tubular.jpg", "length"),

  ...ROOFING_VARIANTS,

  make("Checkered Plate", "Steel Plate", "1.0mm", 3500, "cat-checkered.jpg", "sheet"),
  make("Checkered Plate", "Steel Plate", "1.2mm", 4100, "cat-checkered.jpg", "sheet"),
  make("Checkered Plate", "Steel Plate", "1.5mm", 4800, "cat-checkered.jpg", "sheet"),

  make("Stainless Mirror Finish Sheet", "Stainless Steel Sheet", "0.9mm", 4500, "cat-mirror.jpg", "sheet"),
  make("Stainless Mirror Finish Sheet", "Stainless Steel Sheet", "1.0mm", 4950, "cat-mirror.jpg", "sheet"),
  make("Stainless Mirror Finish Sheet", "Stainless Steel Sheet", "1.2mm", 5800, "cat-mirror.jpg", "sheet"),
  make("Stainless Mirror Finish Sheet", "Stainless Steel Sheet", "1.5mm", 7200, "cat-mirror.jpg", "sheet"),

  make("Stainless Hairline Finish Sheet", "Stainless Steel Sheet", "0.9mm", 4400, "cat-hairline.jpg", "sheet"),
  make("Stainless Hairline Finish Sheet", "Stainless Steel Sheet", "1.0mm", 4850, "cat-hairline.jpg", "sheet"),
  make("Stainless Hairline Finish Sheet", "Stainless Steel Sheet", "1.2mm", 5700, "cat-hairline.jpg", "sheet"),
  make("Stainless Hairline Finish Sheet", "Stainless Steel Sheet", "1.5mm", 7100, "cat-hairline.jpg", "sheet"),

  make("Color Sheet", "Metal Sheets", "4x8 ft", 1850, "cat-colorsheet.jpg", "sheet", true),
  make("Color Sheet", "Metal Sheets", "0.4mm", 1100, "cat-colorsheet.jpg", "sheet"),
  make("Color Sheet", "Metal Sheets", "0.5mm", 1350, "cat-colorsheet.jpg", "sheet"),

  make("Angle Bar", "Stainless Angle Bars", "3mm x 1\"", 680, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "4mm x 1\"", 850, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "5mm x 1\"", 1020, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "3mm x 1 1/2\"", 880, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "4mm x 1 1/2\"", 1100, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "5mm x 1 1/2\"", 1320, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "3mm x 2\"", 1080, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "4mm x 2\"", 1350, "cat-angle.jpg", "length"),
  make("Angle Bar", "Stainless Angle Bars", "5mm x 2\"", 1620, "cat-angle.jpg", "length"),

  make("Stainless Shafting", "Stainless Rods / Shafting", "1/8\"", 180, "cat-shafting.jpg", "length"),
  make("Stainless Shafting", "Stainless Rods / Shafting", "3/16\"", 240, "cat-shafting.jpg", "length"),
  make("Stainless Shafting", "Stainless Rods / Shafting", "1/4\"", 320, "cat-shafting.jpg", "length"),
  make("Stainless Shafting", "Stainless Rods / Shafting", "3/8\"", 480, "cat-shafting.jpg", "length"),
  make("Stainless Shafting", "Stainless Rods / Shafting", "1/2\"", 650, "cat-shafting.jpg", "length"),
  make("Stainless Shafting", "Stainless Rods / Shafting", "5/8\"", 820, "cat-shafting.jpg", "length"),

  make("Decorative Tube", "Stainless Tubes / Pipes", "3/4\"", 580, "cat-deco.jpg", "length"),
  make("Decorative Tube", "Stainless Tubes / Pipes", "1\"", 720, "cat-deco.jpg", "length"),

  make("Tubular Cover", "Stainless Tubes / Pipes", "1\"", 540, "cat-deco.jpg", "length"),
  make("Tubular Cover", "Stainless Tubes / Pipes", "1 1/2\"", 720, "cat-deco.jpg", "length"),
  make("Tubular Cover", "Stainless Tubes / Pipes", "1x2", 880, "cat-deco.jpg", "length"),
  make("Tubular Cover", "Stainless Tubes / Pipes", "2x2", 1080, "cat-deco.jpg", "length"),
  make("Tubular Cover", "Stainless Tubes / Pipes", "2x3", 1450, "cat-deco.jpg", "length"),
  make("Tubular Cover", "Stainless Tubes / Pipes", "1 1/2 x 1", 850, "cat-deco.jpg", "length"),

  make("Drill Bit (HSS)", "Drilling & Fasteners", "1/8\"", 70, "cat-drill.jpg"),
  make("Drill Bit (HSS)", "Drilling & Fasteners", "5/32\"", 85, "cat-drill.jpg"),
  make("Drill Bit (HSS)", "Drilling & Fasteners", "1/4\"", 125, "cat-drill.jpg"),
  make("Drill Bit (HSS)", "Drilling & Fasteners", "3/16\"", 100, "cat-drill.jpg"),
  make("Drill Bit (HSS)", "Drilling & Fasteners", "1/2\"", 240, "cat-drill.jpg"),

  make("Blind Rivets", "Drilling & Fasteners", "1/8 x 1/2", 2.5, "cat-fasteners.jpg", "pc"),
  make("Blind Rivets", "Drilling & Fasteners", "5/32 x 1/2", 3, "cat-fasteners.jpg", "pc"),
  make("Tek Screw", "Drilling & Fasteners", "2\"", 4.5, "cat-fasteners.jpg", "pc"),
  make("Tek Screw", "Drilling & Fasteners", "2 1/2\"", 5.5, "cat-fasteners.jpg", "pc"),

  make("Stainless Ball", "Stainless Accessories", "1 1/2\"", 220, "cat-accessories.jpg"),
  make("Stainless Ball", "Stainless Accessories", "2\"", 320, "cat-accessories.jpg"),
  make("Stainless Ball", "Stainless Accessories", "2 1/2\"", 450, "cat-accessories.jpg"),
  make("Stainless Ball", "Stainless Accessories", "3\"", 620, "cat-accessories.jpg"),

  make("Endcap", "Stainless Accessories", "1\"", 35, "cat-accessories.jpg"),
  make("Endcap", "Stainless Accessories", "1 1/4\"", 45, "cat-accessories.jpg"),
  make("Endcap", "Stainless Accessories", "1 1/2\"", 55, "cat-accessories.jpg"),
  make("Endcap", "Stainless Accessories", "1 3/4\"", 65, "cat-accessories.jpg"),
  make("Endcap", "Stainless Accessories", "2\"", 75, "cat-accessories.jpg"),
  make("Endcap", "Stainless Accessories", "2 1/2\"", 95, "cat-accessories.jpg"),
  make("Endcap", "Stainless Accessories", "3\"", 120, "cat-accessories.jpg"),

  make("Tungsten Rod", "Welding Supplies", "1.6mm", 380, "cat-welding.jpg", "pc"),
  make("Tungsten Rod", "Welding Supplies", "2.0mm", 420, "cat-welding.jpg", "pc"),
  make("Tungsten Rod", "Welding Supplies", "2.4mm", 480, "cat-welding.jpg", "pc"),

  make("Buffing Soap", "Polishing", "Standard", 220, "cat-polishing.jpg", "bar"),

  make("Cylindrical Hinges", "Hardware", "3/8\"", 35, "cat-hardware.jpg", "pair"),
  make("Cylindrical Hinges", "Hardware", "1/2\"", 45, "cat-hardware.jpg", "pair"),
  make("Cylindrical Hinges", "Hardware", "5/8\"", 60, "cat-hardware.jpg", "pair"),
  make("Cylindrical Hinges", "Hardware", "3/4\"", 80, "cat-hardware.jpg", "pair"),
  make("Cylindrical Hinges", "Hardware", "1\"", 110, "cat-hardware.jpg", "pair"),
];

const CATEGORIES = [...new Set(PRODUCTS.map(p => p.category))].sort();

/** True when a catalog product (or its id) may be cut/bent to order. */
const isCustomizable = (productOrId) => {
  const p = typeof productOrId === "string" ? PRODUCTS.find(x => x.id === productOrId) : productOrId;
  return !!(p && p.customizable);
};

// The server reads this same file, so the page and the backend can never
// disagree about what is customizable. (Browsers ignore this line.)
if (typeof module === "object" && module.exports) {
  module.exports = { PRODUCTS, CATEGORIES, CUSTOMIZABLE_NAMES, isCustomizable };
}
