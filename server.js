// server.js (deploy-ready, safe diagnostics, graceful shutdown)
import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import dotenv from "dotenv";
dotenv.config();

/* =========================
   0) ENV VALIDATION / CONFIG
   ========================= */
const REQUIRED = [
  "SHOP",                 // floortaderwholesale.myshopify.com
  "API_VERSION",          // e.g. 2025-07
  "SHOPIFY_ADMIN_TOKEN",  // shpat_...
  "SHOPIFY_API_SECRET"    // from Admin API credentials (App Proxy)
];

const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error("Missing required environment variables:", missing.join(", "));
  process.exit(1);
}

// Optional config with defaults
const DEBUG = process.env.DEBUG_PROXY === "1";
const ALLOW_UNVERIFIED = process.env.ALLOW_UNVERIFIED_PROXY === "1";
const PROXY_PREFIX = process.env.PROXY_PREFIX || "apps";
const PROXY_SUBPATH = process.env.PROXY_SUBPATH || "rfq";
const MOUNT_PREFIX = "/proxy"; // where endpoints are mounted (matches store App Proxy)

if (DEBUG) {
  const t = process.env.SHOPIFY_ADMIN_TOKEN || "";
  console.log("=== DEBUG BOOT ===");
  console.log("SHOP:", process.env.SHOP);
  console.log("API_VERSION:", process.env.API_VERSION);
  console.log("PROXY_PREFIX:", PROXY_PREFIX);
  console.log("PROXY_SUBPATH:", PROXY_SUBPATH);
  console.log("ALLOW_UNVERIFIED_PROXY:", ALLOW_UNVERIFIED ? "1" : "0");
  console.log("ADMIN TOKEN LENGTH:", t.length);
  console.log("==================");
}

/* ===============
   1) APP BOOTSTRAP
   =============== */
const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "100kb" })); // safe default

// Optional CORS (only if you set CORS_ALLOW_ORIGINS)
const CORS_ALLOW = (process.env.CORS_ALLOW_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (CORS_ALLOW.length) {
  app.use((req, res, next) => {
    const o = req.headers.origin || "";
    if (CORS_ALLOW.includes(o)) {
      res.setHeader("Access-Control-Allow-Origin", o);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
      res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    }
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
}

// Small helper logger
const DBG = (...args) => {
  if (DEBUG) console.log("[proxy]", ...args);
};

// Health + root
app.get("/", (_req, res) => res.send("RFQ app running"));
app.get("/healthz", (_req, res) => res.send("ok"));

/* ================================
   2) SHOPIFY APP PROXY VERIFICATION
   ================================ */
function verifyProxySignature(req) {
  try {
    const secret = process.env.SHOPIFY_API_SECRET || "";
    if (!secret) {
      DBG("Missing SHOPIFY_API_SECRET");
      return false;
    }

    // e.g. "/proxy/create-draft-order?shop=...&path_prefix=%2Fapps%2Frfq&timestamp=...&signature=..."
    const originalUrl = req.originalUrl || req.url || "/";
    const qmark = originalUrl.indexOf("?");
    const rawPath = qmark === -1 ? originalUrl : originalUrl.slice(0, qmark);
    const rawQuery = qmark === -1 ? "" : originalUrl.slice(qmark + 1);

    // Extract provided signature OR hmac
    let providedSignature = "";
    if (rawQuery) {
      for (const kv of rawQuery.split("&")) {
        if (kv.startsWith("signature=")) { providedSignature = kv.slice("signature=".length); break; }
        if (kv.startsWith("hmac="))      { providedSignature = kv.slice("hmac=".length);       break; }
      }
    }
    if (!providedSignature) {
      DBG("No signature/hmac in query");
      return false;
    }

    // Remove our own mount prefix from the path
    const serverPathname = rawPath.startsWith(MOUNT_PREFIX)
      ? rawPath.slice(MOUNT_PREFIX.length) // e.g. "/create-draft-order"
      : rawPath;

    // Build storefront path: decoded path_prefix + serverPathname
    let decodedPathPrefix = "";
    if (rawQuery) {
      for (const kv of rawQuery.split("&")) {
        const eq = kv.indexOf("=");
        const key = eq === -1 ? kv : kv.slice(0, eq);
        const val = eq === -1 ? "" : kv.slice(eq + 1);
        if (key === "path_prefix") {
          try { decodedPathPrefix = decodeURIComponent(val || ""); }
          catch { decodedPathPrefix = val || ""; }
          break;
        }
      }
    }
    if (!decodedPathPrefix) decodedPathPrefix = `/${PROXY_PREFIX}/${PROXY_SUBPATH}`;

    const storefrontPath = `${decodedPathPrefix}${serverPathname}`;

    // Keep query string as-is but drop signature/hmac
    let keptQuery = "";
    if (rawQuery) {
      const kept = [];
      for (const kv of rawQuery.split("&")) {
        if (kv.startsWith("signature=") || kv.startsWith("hmac=") || kv === "") continue;
        kept.push(kv);
      }
      keptQuery = kept.join("&");
    }

    // Build message and compute HMAC
    const message = keptQuery ? `${storefrontPath}?${keptQuery}` : storefrontPath;
    const digest = crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");

    const sigBuf = Buffer.from(providedSignature, "utf8");
    const digBuf = Buffer.from(digest, "utf8");
    const ok = sigBuf.length === digBuf.length && crypto.timingSafeEqual(digBuf, sigBuf);

    if (DEBUG) {
      console.log("==== App Proxy HMAC DEBUG ====");
      console.log("originalUrl        :", originalUrl);
      console.log("server pathname    :", serverPathname);
      console.log("decoded path_prefix:", decodedPathPrefix);
      console.log("storefrontPath     :", storefrontPath);
      console.log("raw query          :", rawQuery);
      console.log("keptQuery (ORDER)  :", keptQuery);
      console.log("message (hashed)   :", message);
      console.log("provided signature :", providedSignature);
      console.log("computed digest    :", digest);
      console.log("==============================");
    }

    return ok;
  } catch (e) {
    DBG("verify error:", e);
    return false;
  }
}

// Optional debug endpoint
if (DEBUG) {
  app.get(`${MOUNT_PREFIX}/_debug`, (req, res) => {
    try {
      const originalUrl = req.originalUrl || req.url || "/";
      const qmark = originalUrl.indexOf("?");
      const rawPath = qmark === -1 ? originalUrl : originalUrl.slice(0, qmark);
      const rawQuery = qmark === -1 ? "" : originalUrl.slice(qmark + 1);

      const serverPathname = rawPath.startsWith(MOUNT_PREFIX)
        ? rawPath.slice(MOUNT_PREFIX.length)
        : rawPath;

      let decodedPathPrefix = "";
      if (rawQuery) {
        for (const kv of rawQuery.split("&")) {
          const eq = kv.indexOf("=");
          const key = eq === -1 ? kv : kv.slice(0, eq);
          const val = eq === -1 ? "" : kv.slice(eq + 1);
          if (key === "path_prefix") {
            try { decodedPathPrefix = decodeURIComponent(val || ""); }
            catch { decodedPathPrefix = val || ""; }
            break;
          }
        }
      }
      if (!decodedPathPrefix) decodedPathPrefix = `/${PROXY_PREFIX}/${PROXY_SUBPATH}`;

      const storefrontPath = `${decodedPathPrefix}${serverPathname}`;

      const kept = [];
      if (rawQuery) {
        for (const kv of rawQuery.split("&")) {
          if (kv.startsWith("signature=") || kv.startsWith("hmac=") || kv === "") continue;
          kept.push(kv);
        }
      }
      const keptQuery = kept.join("&");
      const message = keptQuery ? `${storefrontPath}?${keptQuery}` : storefrontPath;

      res.json({
        originalUrl,
        serverPathname,
        decodedPathPrefix,
        storefrontPath,
        rawQuery,
        keptQuery,
        messageHashed: message
      });
    } catch (e) {
      res.status(500).json({ error: String(e) });
    }
  });
}

/* ===================
   3) SHOPIFY ADMIN API
   =================== */
async function adminFetch(path, options = {}) {
  const url = `https://${process.env.SHOP}/admin/api/${process.env.API_VERSION}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "X-Shopify-Access-Token": process.env.SHOPIFY_ADMIN_TOKEN,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  if (!res.ok) {
    const text = await res.text();
    DBG("adminFetch error:", res.status, text);
    throw new Error(`${res.status} ${text}`);
  }
  return res.json();
}

async function findOrCreateCustomer(cust) {
  let id = null;
  if (cust.email) {
    const r = await adminFetch(
      `/customers/search.json?query=${encodeURIComponent(`email:${cust.email}`)}`
    );
    id = r.customers?.[0]?.id || null;
  }
  if (!id) {
    const c = await adminFetch(`/customers.json`, {
      method: "POST",
      body: JSON.stringify({
        customer: {
          email: cust.email,
          first_name: cust.first_name,
          last_name: cust.last_name,
          phone: cust.phone,
          verified_email: !!cust.email
        }
      })
    });
    id = c.customer.id;
  }
  return id;
}

/* ==========================
   4) MAIN RFQ / DRAFT ENDPOINT
   ========================== */

// Disallow GET for safety
app.get(`${MOUNT_PREFIX}/create-draft-order`, (_req, res) =>
  res.status(405).json({ error: "Method Not Allowed" })
);

// Allow preflight explicitly (if CORS is used)
app.options(`${MOUNT_PREFIX}/create-draft-order`, (_req, res) => res.sendStatus(204));

app.post(`${MOUNT_PREFIX}/create-draft-order`, async (req, res) => {
  try {
    DBG("incoming host:", req.headers.host);
    DBG("incoming path:", req.path);
    DBG("incoming query:", req.query);

    if (!ALLOW_UNVERIFIED) {
      const ok = verifyProxySignature(req);
      if (!ok) {
        DBG("HMAC verification FAILED");
        return res.status(401).json({ error: "Invalid HMAC" });
      }
      DBG("HMAC verification PASSED");
    } else {
      DBG("HMAC verification BYPASSED (ALLOW_UNVERIFIED_PROXY=1)");
    }

    const {
      line_items = [],
      customer = {},
      shipping = {},
      note = "",
      installer_needed,
      shipping_method
    } = req.body || {};

    if (!Array.isArray(line_items) || line_items.length === 0) {
      return res.status(400).json({ error: "No line items" });
    }

    const customerId = await findOrCreateCustomer(customer);

    // Pretty note and structured attributes
    const fullName = [customer.first_name, customer.last_name].filter(Boolean).join(" ");
    const contactBits = [
      customer.email && `Email: ${customer.email}`,
      customer.phone && `Phone: ${customer.phone}`,
      customer.company && `Company: ${customer.company}`,
    ].filter(Boolean).join(" • ");

    const shippingAddr = shipping?.address1
      ? [
          shipping.address1,
          shipping.address2,
          [shipping.city, shipping.province, shipping.zip].filter(Boolean).join(", "),
          shipping.country || "United States",
        ].filter(Boolean).join("\n    ")
      : "";

    const prettyNote = [
      "RFQ from storefront",
      fullName && `Customer: ${fullName}`,
      contactBits,
      shipping_method && `Ship method: ${shipping_method}`,
      `Installer needed: ${installer_needed ? "Yes" : "No"}`,
      shippingAddr && `Ship to:\n    ${shippingAddr}`,
      note && `Message: ${note}`,
    ].filter(Boolean).join("\n");

    const note_attributes = [
      { name: "rfq_installer_needed", value: installer_needed ? "Yes" : "No" },
      { name: "rfq_shipping_method",  value: shipping_method || "" },
      { name: "rfq_customer_first_name", value: customer.first_name || "" },
      { name: "rfq_customer_last_name",  value: customer.last_name  || "" },
      { name: "rfq_customer_email",      value: customer.email      || "" },
      { name: "rfq_customer_phone",      value: customer.phone      || "" },
      { name: "rfq_customer_company",    value: customer.company    || "" },
      { name: "rfq_message", value: note || "" },
      { name: "rfq_address1", value: shipping.address1 || "" },
      { name: "rfq_address2", value: shipping.address2 || "" },
      { name: "rfq_city",     value: shipping.city     || "" },
      { name: "rfq_province", value: shipping.province || "" },
      { name: "rfq_zip",      value: shipping.zip      || "" },
      { name: "rfq_country",  value: shipping.country  || "" },
    ].filter(p => (p.value ?? "") !== "");

    const payload = {
      draft_order: {
        line_items: line_items.map((li) => ({
          ...(li.variant_id
            ? { variant_id: Number(li.variant_id) }
            : { title: li.title, price: li.price }),
          quantity: Number(li.quantity || 1),
          properties: li.properties || []
        })),
        customer: { id: customerId },
        shipping_address: shipping?.address1
          ? {
              first_name: customer.first_name || "",
              last_name:  customer.last_name  || "",
              phone:      customer.phone      || "",
              address1:   shipping.address1,
              address2:   shipping.address2 || "",
              city:       shipping.city     || "",
              province:   shipping.province || "",
              zip:        shipping.zip      || "",
              country:    shipping.country  || "United States",
              company:    customer.company  || ""
            }
          : undefined,
        note: prettyNote,
        note_attributes,
        tags: "RFQ,DraftOrder,WebForm",
        use_customer_default_address: true
      }
    };

    DBG("creating draft order with payload:", JSON.stringify(payload));

    const out = await adminFetch(`/draft_orders.json`, {
      method: "POST",
      body: JSON.stringify(payload)
    });

    const id = out?.draft_order?.id;
    const invoice = out?.draft_order?.invoice_url || null;
    if (!id) throw new Error("No draft order id returned");

    const adminUrl = `https://${process.env.SHOP}/admin/draft_orders/${id}`;
    DBG("draft_order_id:", id, "admin_url:", adminUrl, "invoice_url:", invoice);

    // Default response: reference + admin link (+invoice if you want to open later)
    if (req.query.verbose === "1") {
      return res.json({
        reference: id,
        admin_url: adminUrl,
        draft_order_id: id,
        invoice_url: invoice
      });
    }
    return res.json({ reference: id, admin_url: adminUrl, invoice_url: invoice });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/* ==================
   5) FALLBACK / ERRORS
   ================== */
app.use((req, res) => {
  res.status(404).json({ error: "Not Found" });
});

/* =======================
   6) START & GRACEFUL STOP
   ======================= */
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`Listening on ${port}`);
});

function shutdown(signal) {
  console.log(`\n${signal} received, shutting down…`);
  server.close(() => {
    console.log("HTTP server closed.");
    process.exit(0);
  });
  // Force-exit if close hangs
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
