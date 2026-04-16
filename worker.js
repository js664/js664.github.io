export default {
  async fetch(request, env, ctx) {
    // 1. Allow CORS (so your website can talk to this worker)
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    if (request.method !== "POST") {
      return new Response("Not Allowed", { status: 405 });
    }

    const BOT_TOKEN = env.TELEGRAM_BOT_TOKEN;
    const CHAT_ID = env.TELEGRAM_CHAT_ID;

    try {
      // Get location data solely from Cloudflare's standard headers (not identifiable)
      const country = request.cf?.country || "Earth";
      const city = request.cf?.city || "Unknown City";
      const ua = request.headers.get("user-agent") || "No UA";
      
      const message = `📍 *New Entry*\nLocation: ${city}, ${country}\nUA: ${ua}`;
      
      const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: CHAT_ID,
          text: message,
          parse_mode: "Markdown",
        }),
      });

      const result = await response.json();

      return new Response(JSON.stringify(result), {
        headers: { 
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*" 
        },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { 
        status: 500,
        headers: { "Access-Control-Allow-Origin": "*" }
      });
    }
  },
};
