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
 * Query param      : ?signature=<hex> (App Proxy) or ?hmac=<hex> (other flows)
 *
 * IMPORTANT: We must preserve the ORIGINAL query-string ORDER.
 * Shopify computes HMAC using the exact order they sent.
 */
function verifyProxySignature(req) {
  try {
    const originalUrl = req.originalUrl || req.url || "/";

    // Use ?shop= if present (preview domains differ)
    const tmpQs = originalUrl.split("?")[1] || "";
    const tmpParams = new URLSearchParams(tmpQs);
    const shopParam = (tmpParams.get("shop") || "").toLowerCase();
    const baseShop = shopParam || (process.env.SHOP || "").toLowerCase();

    const url = new URL(originalUrl, `https://${baseShop}`);
    const params = new URLSearchParams(url.search);

    // Prefer `signature` (App Proxy), fallback to `hmac`
    const provided = params.get("signature") || params.get("hmac");
    if (!provided) {
      DBG("NO signature/hmac param found");
      DBG("originalUrl =", originalUrl);
      DBG("baseShop   =", baseShop);
      DBG("pathname   =", url.pathname);
      DBG("search     =", url.search);
      return false;
    }

    // Build storefront path from /proxy/... -> /apps/<subpath>/...
    const pathPrefix = `/${process.env.PROXY_PREFIX || "apps"}/${process.env.PROXY_SUBPATH || "rfq"}`;
    const storefrontPath = url.pathname.replace(/^\/proxy/, pathPrefix);

    // Rebuild the query string in ORIGINAL order, excluding signature/hmac
    const orderedPairs = [];
    for (const [k, v] of params.entries()) {
      if (k === "signature" || k === "hmac") continue;
      // Keep the exact encoding Shopify expects via URLSearchParams
      orderedPairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
    const keptQuery = orderedPairs.join("&");

    // Message to hash (no '?' when no params)
    const message = keptQuery ? `${storefrontPath}?${keptQuery}` : storefrontPath;

    const secret = process.env.SHOPIFY_API_SECRET || "";
    const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");

    if (process.env.DEBUG_PROXY === "1") {
      console.log("==== App Proxy HMAC DEBUG ====");
      console.log("shop param         :", shopParam || "(none)");
      console.log("baseShop used      :", baseShop);
      console.log("originalUrl        :", originalUrl);
      console.log("server pathname    :", url.pathname);
      console.log("storefrontPath     :", storefrontPath);
      console.log("raw query          :", url.search);
      console.log("keptQuery (ORDER)  :", keptQuery);
      console.log("message (hashed)   :", message);
      console.log("provided signature :", provided);
      console.log("computed digest    :", digest);
      console.log(
        "secret len/preview :", secret.length,
        secret ? secret.slice(0, 4) + "..." + secret.slice(-4) : "(empty)"
      );
      console.log("==============================");
    }

    // timing-safe compare (avoid throw on length mismatch)
    const sigBuf = Buffer.from(provided, "utf8");
    const digBuf = Buffer.from(digest, "utf8");
    if (sigBuf.length !== digBuf.length) return false;

    return crypto.timingSafeEqual(digBuf, sigBuf);
  } catch (e) {
    DBG("verify error:", e);
    return false;
  }
}

/** Optional debug endpoint: shows what the server WILL hash (no verification). */
if (process.env.DEBUG_PROXY === "1") {
  app.get("/proxy/_debug", (req, res) => {
    try {
      const originalUrl = req.originalUrl || req.url || "/";

      const tmpQs = originalUrl.split("?")[1] || "";
      const tmpParams = new URLSearchParams(tmpQs);
      const shopParam = (tmpParams.get("shop") || "").toLowerCase();
      const baseShop = shopParam || (process.env.SHOP || "").toLowerCase();

      const url = new URL(originalUrl, `https://${baseShop}`);
      const params = new URLSearchParams(url.search);

      const pathPrefix = `/${process.env.PROXY_PREFIX || "apps"}/${process.env.PROXY_SUBPATH || "rfq"}`;
      const storefrontPath = url.pathname.replace(/^\/proxy/, pathPrefix);

      const orderedPairs = [];
      for (const [k, v] of params.entries()) {
        if (k === "signature" || k === "hmac") continue;
        orderedPairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
      }
      const keptQuery = orderedPairs.join("&");
      const message = keptQuery ? `${storefrontPath}?${keptQuery}` : storefrontPath;

      res.json({
        shopParam: shopParam || "(none)",
        baseShop,
        originalUrl,
        serverPathname: url.pathname,
        storefrontPath,
        rawQuery: url.search,
        keptQuery,
        messageHashed: message
      });
    } catch (e) {
      res.status(500).json({ error: String(e) });
    }
  });
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
    // Quick visibility while debugging
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
