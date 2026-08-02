export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const PUSHOVER_TOKEN = env?.PUSHOVER_TOKEN || "";
    const PUSHOVER_USER_KEY = env?.PUSHOVER_USER_KEY || "";
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { ...cors, "Content-Type": "application/json" },
      });

    try {

    const arrayBufferToBase64 = (buffer) => {
      const bytes = new Uint8Array(buffer);
      const chunkSize = 0x8000;
      let binary = "";
      for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
      }
      return btoa(binary);
    };
     const sendPushover = async ({ title, message, imageBase64, imageMime, url: msgUrl, urlTitle }) => {
      try {
        if (!PUSHOVER_TOKEN || !PUSHOVER_USER_KEY) {
          console.warn("Pushover credentials are not configured in worker env");
          return;
        }
        const fd = new FormData();
        fd.append("token",    PUSHOVER_TOKEN);
        fd.append("user",     PUSHOVER_USER_KEY);
        fd.append("title",    title);
        fd.append("message",  message);
        fd.append("sound",    "cashregister");
        fd.append("priority", "1");
        fd.append("html",     "1");

        if (msgUrl)   fd.append("url",       msgUrl);
        if (urlTitle) fd.append("url_title",  urlTitle);

        if (imageBase64) {
          const binary = atob(imageBase64);
          const bytes  = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
          const blob = new Blob([bytes], { type: imageMime || "image/jpeg" });
          fd.append("attachment", blob, "receipt.jpg");
        }

        const res = await fetch("https://api.pushover.net/1/messages.json", {
          method: "POST",
          body: fd,
        });
        if (!res.ok) console.error("Pushover failed:", await res.text());
      } catch (e) {
        console.error("Pushover error:", e.message);
      }
    };
     if (url.pathname === "/api/request-pro" && request.method === "POST") {
      if (!env?.PRO_PINS) return json({ error: "PRO_PINS KV not configured" }, 500);
      const contentType = request.headers.get("Content-Type") || "";
      let name, email, method, imageBase64, imageMime;

      if (contentType.includes("multipart/form-data")) {
        const formData = await request.formData();
        name   = formData.get("name");
        email  = formData.get("email");
        method = formData.get("method");
        const imageFile = formData.get("image");
        if (imageFile && imageFile.size > 0) {
          imageMime = imageFile.type || "image/jpeg";
          const buf = await imageFile.arrayBuffer();
          imageBase64 = arrayBufferToBase64(buf);
        }
      } else {
        const body  = await request.json();
        name        = body.name;
        email       = body.email;
        method      = body.method;
        imageBase64 = body.receiptBase64 || body.imageBase64 || null;
        imageMime   = body.receiptType   || body.imageMime   || "image/jpeg";
      }

      if (!name || !email || !method) {
        return json({ error: "Missing required fields" }, 400);
      }
       const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";
      const pin   = Array.from({ length: 14 }, () =>
        chars[Math.floor(Math.random() * chars.length)]
      ).join("");
       await env.PRO_PINS.put(pin, JSON.stringify({
        email,
        name,
        isActive: true,
        createdAt: new Date().toISOString(),
      }), { expirationTtl: 2592000 });

      console.log("PIN saved to KV:", pin);

      const methodLabel = method === "binance" ? "Binance Pay" : "UBL Bank Transfer";
      const formattedMessage = [
        `<b>👤 Name:</b> ${name}`,
        `<b>📧 Email:</b> ${email}`,
        `<b>💳 Method:</b> ${methodLabel}`,
        ``,
        `<b>🔑 PIN to send:</b>`,
        `<font color="#f59e0b"><b>${pin}</b></font>`,
        ``,
        `<i>Send PIN to ${email} within 2 hours.</i>`,
      ].join("\n");

      await sendPushover({
        title:    "💰 NEW PRO SALE — Action Required",
        message:  formattedMessage,
        imageBase64,
        imageMime,
        url:      `mailto:${email}?subject=Your SyncBoard Pro PIN&body=Hi ${name},%0A%0AYour Pro PIN is: ${pin}%0A%0AThank you!`,
        urlTitle: `Email ${name} their PIN`,
      });

      return json({ success: true });
    }
     if (url.pathname === "/api/verify-pin" && request.method === "POST") {
      if (!env?.PRO_PINS) return json({ error: "PRO_PINS KV not configured" }, 500);
      const { pin } = await request.json();
      if (!pin) return json({ valid: false });

      const normalizedPin = pin.trim().toUpperCase();
      const stored = await env.PRO_PINS.get(normalizedPin);
      if (!stored) {
        console.log(`Verify [${normalizedPin}]: not found in KV`);
        return json({ valid: false });
      }

      const record = JSON.parse(stored);
      const valid  = record.isActive === true;
      console.log(`Verify [${normalizedPin}]: valid=${valid}`);
      return json({ valid, email: record.email });
    }
     if (url.pathname === "/api/debug-pin" && request.method === "POST") {
      if (!env?.PRO_PINS) return json({ error: "PRO_PINS KV not configured" }, 500);
      const { pin } = await request.json();
      const normalizedPin = pin.trim().toUpperCase();
      const stored = await env.PRO_PINS.get(normalizedPin);
      return json({
        query:    normalizedPin,
        found:    !!stored,
        document: stored ? JSON.parse(stored) : null,
      });
    }
     if (url.pathname === "/api/list-pins" && request.method === "GET") {
      if (!env?.PRO_PINS) return json({ error: "PRO_PINS KV not configured" }, 500);
      const list = await env.PRO_PINS.list();
      return json({ keys: list.keys });
    }
     if (url.pathname === "/api/revoke-pin" && request.method === "POST") {
      if (!env?.PRO_PINS) return json({ error: "PRO_PINS KV not configured" }, 500);
      const { pin, secret } = await request.json();
      if (secret !== env.ADMIN_SECRET) return json({ error: "Unauthorized" }, 401);
      const normalizedPin = pin.trim().toUpperCase();
      const stored = await env.PRO_PINS.get(normalizedPin);
      if (!stored) return json({ error: "PIN not found" }, 404);
      const record = JSON.parse(stored);
      record.isActive = false;
      await env.PRO_PINS.put(normalizedPin, JSON.stringify(record));
      return json({ success: true, pin: normalizedPin });
    }

      return new Response("SyncBoard API Active ✓", { status: 200, headers: cors });
    } catch (err) {
      return json({ error: "Worker error", message: err?.message || "Unknown error" }, 500);
    }
  },
};
