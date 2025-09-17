import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(express.json());

// simple root so admin shows something
app.get("/", (_req, res) => res.send("RFQ app running"));

// verify App Proxy HMAC (Shopify adds ?hmac=… to proxy requests)
function verifyProxyHmac(req) {
  const qs = req.url.split("?")[1] || "";
  const params = new URLSearchParams(qs);
  const hmac = params.get("hmac") || "";
  params.delete("hmac");
  const message = params.toString();
  const digest = crypto.createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(message).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac)); }
  catch { return false; }
}

async function adminFetch(path, options = {}) {
  const url = `https://${process.env.SHOP}/admin/api/${process.env.API_VERSION}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "X-Shopify-Access-Token": process.env.SHOPIFY_ADMIN_TOKEN,
      "Content-Type": "application/json"
    }
  });
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

async function findOrCreateCustomer(cust) {
  let id = null;
  if (cust.email) {
    const r = await adminFetch(`/customers/search.json?query=email:${encodeURIComponent(cust.email)}`);
    id = r.customers?.[0]?.id || null;
  }
  if (!id) {
    const c = await adminFetch(`/customers.json`, {
      method: "POST",
      body: JSON.stringify({ customer: {
        email: cust.email, first_name: cust.first_name,
        last_name: cust.last_name, phone: cust.phone,
        verified_email: !!cust.email
      }})
    });
    id = c.customer.id;
  }
  return id;
}

// MAIN endpoint used by your form (via App Proxy)
app.post("/proxy/create-draft-order", async (req, res) => {
  try {
    if (!verifyProxyHmac(req)) return res.status(401).json({ error: "Invalid HMAC" });

    const { line_items = [], customer = {}, shipping = {}, note = "", installer_needed, shipping_method } = req.body || {};
    if (!Array.isArray(line_items) || !line_items.length) {
      return res.status(400).json({ error: "No line items" });
    }

    const customerId = await findOrCreateCustomer(customer);

    const payload = {
      draft_order: {
        line_items: line_items.map(li => ({
          ...(li.variant_id ? { variant_id: Number(li.variant_id) } : { title: li.title, price: li.price }),
          quantity: Number(li.quantity || 1),
          properties: li.properties || []
        })),
        customer: { id: customerId },
        shipping_address: shipping?.address1 ? {
          first_name: customer.first_name, last_name: customer.last_name, phone: customer.phone,
          address1: shipping.address1, address2: shipping.address2 || "", city: shipping.city || "",
          province: shipping.province || "", zip: shipping.zip || "", country: shipping.country || "United States",
          company: shipping.company || ""
        } : undefined,
        note: [
          "RFQ from storefront",
          `Installer needed: ${installer_needed ? "Yes" : "No"}`,
          `Ship method: ${shipping_method || "N/A"}`,
          note || ""
        ].filter(Boolean).join(" | "),
        tags: "RFQ,DraftOrder",
        use_customer_default_address: true
      }
    };

    const out = await adminFetch(`/draft_orders.json`, { method: "POST", body: JSON.stringify(payload) });
    const invoice = out?.draft_order?.invoice_url;
    if (!invoice) throw new Error("No invoice_url returned");
    res.json({ invoice_url: invoice, draft_order_id: out.draft_order.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(process.env.PORT || 3000, ()=>console.log("Listening"));
