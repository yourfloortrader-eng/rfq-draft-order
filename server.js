// server.js
import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.set("trust proxy", true);
app.use(express.json());

// Simple logger gated by DEBUG_PROXY=1
const DBG = (...args) => {
  if (process.env.DEBUG_PROXY === "1") console.log("[proxy]", ...args);
};

// Root + health
app.get("/", (_req, res) => res.send("RFQ app running"));
app.get("/healthz", (_req, res) => res.send("ok"));

/**
 * Verify Shopify App Proxy signature.
 * Storefront path  : /apps/<subpath>/...
 * Your server path : /proxy/...
 * Query param      : ?signature=<hex> (HMAC-SHA256)
 */
function verifyProxySignature(req) {
  try {
    // Build URL from the request using SHOP (.myshopify.com) as base for consistent parsing
    const url = new URL(req.originalUrl, `https://${process.env.SHOP}`);

    const params = new URLSearchParams(url.search);
    const signature = params.get("signature");
    if (!signature) {
      DBG("NO signature param; originalUrl=", req.originalUrl);
      return false;
    }

    // Remove signature before hashing
    params.delete("signature");

    // Convert /proxy/... back to /apps/<subpath>/...
    const storefrontPath = url.pathname.replace(
      /^\/proxy/,
      `/${process.env.PROXY_PREFIX || "apps"}/${process.env.PROXY_SUBPATH || "rfq"}`
    );

    const message = `${storefrontPath}?${params.toString()}`;

    const digest = crypto
      .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
      .update(message)
      .digest("hex");

    // Verbose debug
    DBG("originalUrl:", req.originalUrl);
    DBG("storefrontPath:", storefrontPath);
    DBG("message     :", message);
    DBG("signature   :", signature);
    DBG("digest      :", digest);

    // Compare in constant time
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch (e) {
    DBG("verify error:", e);
    return false;
  }
}

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

// MAIN endpoint (called from your storefront via App Proxy)
app.post("/proxy/create-draft-order", async (req, res) => {
  try {
    // Optional quick view of incoming headers/query when debugging
    DBG("incoming host:", req.headers.host);
    DBG("incoming path:", req.path);
    DBG("incoming query:", req.query);

    if (process.env.ALLOW_UNVERIFIED_PROXY !== "1") {
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
              last_name: customer.last_name || "",
              phone: customer.phone || "",
              address1: shipping.address1,
              address2: shipping.address2 || "",
              city: shipping.city || "",
              province: shipping.province || "",
              zip: shipping.zip || "",
              country: shipping.country || "United States",
              company: shipping.company || ""
            }
          : undefined,
        note: [
          "RFQ from storefront",
          `Installer needed: ${installer_needed ? "Yes" : "No"}`,
          `Ship method: ${shipping_method || "N/A"}`,
          note || ""
        ]
          .filter(Boolean)
          .join(" | "),
        tags: "RFQ,DraftOrder",
        use_customer_default_address: true
      }
    };

    DBG("creating draft order with payload:", JSON.stringify(payload));

    const out = await adminFetch(`/draft_orders.json`, {
      method: "POST",
      body: JSON.stringify(payload)
    });

    const invoice = out?.draft_order?.invoice_url;
    if (!invoice) throw new Error("No invoice_url returned");

    DBG("draft_order_id:", out.draft_order.id, "invoice_url:", invoice);

    res.json({
      invoice_url: invoice,
      draft_order_id: out.draft_order.id
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Listening on ${port}`);
  if (process.env.DEBUG_PROXY === "1") {
    console.log("DEBUG_PROXY is ON");
    console.log("Env summary:", {
      SHOP: process.env.SHOP,
      API_VERSION: process.env.API_VERSION,
      PROXY_PREFIX: process.env.PROXY_PREFIX,
      PROXY_SUBPATH: process.env.PROXY_SUBPATH,
      ALLOW_UNVERIFIED_PROXY: process.env.ALLOW_UNVERIFIED_PROXY || "0"
    });
  }
});
