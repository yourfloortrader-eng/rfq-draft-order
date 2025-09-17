import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.set("trust proxy", true);
app.use(express.json());

// Root + health
app.get("/", (_req, res) => res.send("RFQ app running"));
app.get("/healthz", (_req, res) => res.send("ok"));

/**
 * Verify Shopify App Proxy signature.
 * Shopify forwards storefront calls from:
 *   /apps/<subpath>/...  (storefront path)
 * to your server at:
 *   /proxy/...           (server path)
 *
 * It includes a ?signature=<hex> query param.
 * The signature is HMAC-SHA256 over:
 *   <storefrontPath>?<canonicalQueryWithoutSignature>
 */
function verifyProxySignature(req) {
  try {
    // Use shop domain as base so URL parsing is consistent
    const url = new URL(req.originalUrl, `https://${process.env.SHOP}`);

    const params = new URLSearchParams(url.search);
    const signature = params.get("signature");
    if (!signature) return false;

    // Canonicalize by removing signature
    params.delete("signature");

    // Convert our server path (/proxy/...) back to the original storefront path (/apps/<subpath>/...)
    const storefrontPath = url.pathname.replace(
      /^\/proxy/,
      `/${process.env.PROXY_PREFIX || "apps"}/${process.env.PROXY_SUBPATH || "rfq"}`
    );

    const message = `${storefrontPath}?${params.toString()}`;

    const digest = crypto
      .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
      .update(message)
      .digest("hex");

    // timing-safe comparison
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch {
    return false;
  }
}

async function adminFetch(path, options = {}) {
  // SHOP **must** be your .myshopify.com domain
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

// MAIN endpoint used by your storefront through the App Proxy
app.post("/proxy/create-draft-order", async (req, res) => {
  try {
    if (process.env.ALLOW_UNVERIFIED_PROXY !== "1") {
      if (!verifyProxySignature(req)) {
        return res.status(401).json({ error: "Invalid HMAC" });
      }
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
        shipping_address:
          shipping?.address1
            ? {
                first_name: customer.first_name,
                last_name: customer.last_name,
