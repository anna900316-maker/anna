import type { Context } from "https://edge.netlify.com";

const COOKIE = "tokyo_trusted";
const DAYS = 180;
const encoder = new TextEncoder();

function page(message = "") {
  return new Response(`<!doctype html><html lang="zh-Hant"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Tokyo Travel Book</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(145deg,#fff6fb,#f3f0ff 48%,#ecf9ff);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#37334c}.card{width:min(86vw,360px);padding:30px;border-radius:28px;background:#fffdfd;box-shadow:0 18px 55px #79679328;text-align:center}.eyebrow{letter-spacing:3px;font-size:11px;color:#856fa5;font-weight:700}h1{font:43px Georgia,serif;letter-spacing:3px;margin:16px 0 6px}.date{font:15px Georgia,serif;color:#6e6682}p{font-size:13px;color:#817b97;line-height:1.6;margin:18px 0}input,button{width:100%;box-sizing:border-box;border-radius:14px;padding:13px;font:inherit}input{border:1px solid #e8e1ee;background:#fdfbff;margin-bottom:10px}button{border:0;background:#8870bd;color:white;font-weight:700}.error{color:#b55872}</style><main class="card"><div class="eyebrow">TRAVEL BOOK</div><h1>TOKYO</h1><div class="date">2026.09.05–09.14</div><p>輸入旅行手冊密碼以繼續。</p>${message ? `<p class="error">${message}</p>` : ""}<form method="post" action="/_auth/login"><input type="password" name="password" autocomplete="current-password" placeholder="旅行手冊密碼" required autofocus><button>進入旅程</button></form></main></html>`, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
function cookie(request: Request) { return request.headers.get("cookie")?.split(";").map(x => x.trim()).find(x => x.startsWith(COOKIE + "="))?.slice(COOKIE.length + 1); }
async function key(secret: string) { return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); }
function bytes(value: string) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
async function sign(payload: string, secret: string) { return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", await key(secret), encoder.encode(payload))))); }
async function valid(token: string | undefined, secret: string) { try { if (!token) return false; const [payload, signature] = token.split("."); if (!payload || !signature) return false; if (!(await crypto.subtle.verify("HMAC", await key(secret), bytes(signature), encoder.encode(payload)))) return false; return JSON.parse(atob(payload)).exp > Date.now(); } catch { return false; } }
function session(secret: string) { const payload = btoa(JSON.stringify({ exp: Date.now() + DAYS * 864e5, nonce: crypto.randomUUID() })); return sign(payload, secret).then(signature => `${payload}.${signature}`); }

export default async (request: Request, context: Context) => {
  const url = new URL(request.url);
  const password = Netlify.env.get("SITE_PASSWORD");
  if (!password) return new Response("網站保護設定未完成。", { status: 503, headers: { "cache-control": "no-store" } });
  if (url.pathname === "/_auth/logout") return new Response(null, { status: 302, headers: { location: "/_auth/login", "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
  if (url.pathname === "/_auth/login") {
    if (request.method !== "POST") return page();
    const form = await request.formData();
    if (form.get("password") !== password) return page("密碼不正確，請再試一次。");
    const token = await session(password);
    return new Response(null, { status: 303, headers: { location: "/", "set-cookie": `${COOKIE}=${token}; Path=/; Max-Age=${DAYS * 86400}; HttpOnly; Secure; SameSite=Lax` } });
  }
  if (!(await valid(cookie(request), password))) return new Response(null, { status: 302, headers: { location: "/_auth/login", "cache-control": "no-store" } });
  const response = await context.next();
  const headers = new Headers(response.headers); headers.set("cache-control", "private, no-store");
  return new Response(response.body, { status: response.status, headers });
};
