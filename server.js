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
 * Verify Shopify App Proxy signature using the RAW query string.
 *
 * What we hash:
 *   <decoded path_prefix><serverPathname>?<rawQueryString WITHOUT signature/hmac>
 *
 * Example final message (from your logs):
 *   /apps/rfq/create-draft-order?shop=v190v1-i8.myshopify.com&logged_in_customer_id=&path_prefix=%2Fapps%2Frfq&timestamp=1758218963
 *
 * Notes:
 * - We do NOT decode/re-encode the kept query string.
 * - We keep original order and encoding of all pairs except we remove `signature=` (or `hmac=`).
 * - `path_prefix` is used ONLY to build the path (decoded), not modified in the query.
 */
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
    const rawQuery = qmark === -1 ? "" : originalUrl.slice(qmark + 1); // no leading "?"

    // --- 1) Extract provided signature (or hmac) directly from the raw query
    let providedSignature = "";
    if (rawQuery) {
      // find "signature=" or "hmac=" pairs (App Proxy uses `signature`)
      const pairs = rawQuery.split("&");
      for (const kv of pairs) {
        if (kv.startsWith("signature=")) {
          providedSignature = kv.slice("signature=".length);
          break;
        }
        if (kv.startsWith("hmac=")) {
          providedSignature = kv.slice("hmac=".length);
          break;
        }
      }
    }
    if (!providedSignature) {
      DBG("No signature/hmac in query");
      return false;
    }

    // --- 2) Build the storefront path:
    // serverMountPrefix = "/proxy" (your Render/Express mount)
    const serverMountPrefix = "/proxy";
    const serverPathname = rawPath.startsWith(serverMountPrefix)
      ? rawPath.slice(serverMountPrefix.length) // e.g. "/create-draft-order"
      : rawPath;

    // Read path_prefix from the RAW query without changing order.
    // We must decode ONLY the value we use to build the path.
    let decodedPathPrefix = "";
    if (rawQuery) {
      const pairs = rawQuery.split("&");
      for (const kv of pairs) {
        const eq = kv.indexOf("=");
        const key = eq === -1 ? kv : kv.slice(0, eq);
        const val = eq === -1 ? "" : kv.slice(eq + 1);
        if (key === "path_prefix") {
          // decode just for the path construction
          try {
            decodedPathPrefix = decodeURIComponent(val || "");
          } catch {
            decodedPathPrefix = val || "";
          }
          break;
        }
      }
    }

    // Fallback if env is used
    if (!decodedPathPrefix) {
      const fallback = `/${process.env.PROXY_PREFIX || "apps"}/${process.env.PROXY_SUBPATH || "rfq"}`;
      decodedPathPrefix = fallback;
    }

    // storefrontPath = decoded path_prefix + serverPathname
    const storefrontPath = `${decodedPathPrefix}${serverPathname}`;

    // --- 3) Keep the RAW query string but drop ONLY the signature/hmac pair(s).
    // Preserve original order and encoding of all other pairs.
    let keptQuery = "";
    if (rawQuery) {
      const kept = [];
      for (const kv of rawQuery.split("&")) {
        if (
          kv.startsWith("signature=") ||
          kv.startsWith("hmac=") ||
          kv === "" // ignore empty fragments
        ) {
          continue;
        }
        kept.push(kv);
      }
      keptQuery = kept.join("&");
    }

    // --- 4) Final message to hash (include "?" only if there are params)
    const message = keptQuery ? `${storefrontPath}?${keptQuery}` : storefrontPath;

    // --- 5) Compute digest
    const digest = crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");

    // --- 6) Timing-safe compare
    const sigBuf = Buffer.from(providedSignature, "utf8");
    const digBuf = Buffer.from(digest, "utf8");
    const ok = sigBuf.length === digBuf.length && crypto.timingSafeEqual(digBuf, sigBuf);

    if (process.env.DEBUG_PROXY === "1") {
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
      console.log(
        "secret len/preview :", secret.length,
        secret ? secret.slice(0, 4) + "..." + secret.slice(-4) : "(empty)"
      );
      console.log("==============================");
    }

    return ok;
  } catch (e) {
    DBG("verify error:", e);
    return false;
  }
}

/** Optional debug endpoint to show what we will hash (no verification). */
if (process.env.DEBUG_PROXY === "1") {
  app.get("/proxy/_debug", (req, res) => {
    try {
      const originalUrl = req.originalUrl || req.url || "/";
      const qmark = originalUrl.indexOf("?");
      const rawPath = qmark === -1 ? originalUrl : originalUrl.slice(0, qmark);
      const rawQuery = qmark === -1 ? "" : originalUrl.slice(qmark + 1);

      const serverMountPrefix = "/proxy";
      const serverPathname = rawPath.startsWith(serverMountPrefix)
        ? rawPath.slice(serverMountPrefix.length)
        : rawPath;

      let decodedPathPrefix = "";
      if (rawQuery) {
        for (const kv of rawQuery.split("&")) {
          const eq = kv.indexOf("=");
          const key = eq === -1 ? kv : kv.slice(0, eq);
          const val = eq === -1 ? "" : kv.slice(eq + 1);
          if (key === "path_prefix") {
            try {
              decodedPathPrefix = decodeURIComponent(val || "");
            } catch {
              decodedPathPrefix = val || "";
            }
            break;
          }
        }
      }
      if (!decodedPathPrefix) {
        decodedPathPrefix = `/${process.env.PROXY_PREFIX || "apps"}/${process.env.PROXY_SUBPATH || "rfq"}`;
      }

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
