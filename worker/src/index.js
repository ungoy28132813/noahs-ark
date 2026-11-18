// NOAH'S ARK RETRUNS - backend Worker
// Routes: /api/neighbors (news gossip), /api/t (analytics beacon), /api/chat (live chat),
//         /api/admin/login|stats|chat/hide (password-protected admin), cron alert push via ntfy.
// Everything else is served from the static assets binding (site/index.html, site/admin.html, site/sw.js).

const LAT = 28.08, LON = -80.61; // Melbourne, FL at city level only (never a home address)
const CRIT = /(Flash Flood (Warning|Emergency)|Tornado (Warning|Emergency)|Severe Thunderstorm Warning|Hurricane (Force Wind )?Warning|Tropical Storm Warning|Storm Surge Warning|Extreme Wind Warning|Flood Warning|Coastal Flood Warning|Tsunami Warning|Storm Warning|Special Marine Warning)/i;
const STATES = {AL:"Alabama",AK:"Alaska",AZ:"Arizona",AR:"Arkansas",CA:"California",CO:"Colorado",CT:"Connecticut",DE:"Delaware",FL:"Florida",GA:"Georgia",HI:"Hawaii",ID:"Idaho",IL:"Illinois",IN:"Indiana",IA:"Iowa",KS:"Kansas",KY:"Kentucky",LA:"Louisiana",ME:"Maine",MD:"Maryland",MA:"Massachusetts",MI:"Michigan",MN:"Minnesota",MS:"Mississippi",MO:"Missouri",MT:"Montana",NE:"Nebraska",NV:"Nevada",NH:"New Hampshire",NJ:"New Jersey",NM:"New Mexico",NY:"New York",NC:"North Carolina",ND:"North Dakota",OH:"Ohio",OK:"Oklahoma",OR:"Oregon",PA:"Pennsylvania",RI:"Rhode Island",SC:"South Carolina",SD:"South Dakota",TN:"Tennessee",TX:"Texas",UT:"Utah",VT:"Vermont",VA:"Virginia",WA:"Washington",WV:"West Virginia",WI:"Wisconsin",WY:"Wyoming",DC:"District of Columbia",PR:"Puerto Rico"};
const FILTER = {
  stuck: /rescue|stranded|trapped|stuck|swept|submerged/i,
  animals: /animal|\bdogs?\b|\bcats?\b|horse|cattle|livestock|alligator|gator|manatee|\bpets?\b|puppy|kitten/i,
  missing: /missing|search(ing|ed)? for|swept away|unaccounted/i,
  deaths: /fatal|death|dead|died|drown|killed|body found/i
};
const RELEVANT = /flood|rain|storm|water|drown|swept|rescue|surge/i;
const BOT = /bot|crawl|spider|headless|preview|facebookexternalhit|slurp|monitor|curl|wget|python|lighthouse/i;
const PLATS = ["Facebook","Instagram","Messenger","Threads","TikTok","X / Twitter","YouTube","Reddit","LinkedIn","Pinterest","Snapchat","WhatsApp","Telegram","Google","Direct / Other"];
const enc = new TextEncoder();
let schemaReady = false;

/* ---------- helpers ---------- */
const hex = (buf) => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
async function sha256hex(s) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
function safeEq(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
async function hmac(env, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(env.ADMIN_PASSWORD_HASH), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
function json(obj, status, extra) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: Object.assign({ "content-type": "application/json;charset=UTF-8", "cache-control": "no-store" }, extra || {}) });
}
function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return {};
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (allowed.indexOf("*") >= 0 || allowed.indexOf(origin) >= 0 || origin === new URL(request.url).origin) {
    return { "Access-Control-Allow-Origin": origin, "Vary": "Origin", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Max-Age": "600" };
  }
  return {};
}
function withCors(resp, request, env) {
  const h = corsHeaders(request, env);
  const r = new Response(resp.body, resp);
  Object.keys(h).forEach(k => r.headers.set(k, h[k]));
  return r;
}
async function authed(request, env) {
  if (!env.ADMIN_PASSWORD_HASH) return false;
  const m = (request.headers.get("Authorization") || "").match(/^Bearer (\d+)\.([a-f0-9]{64})$/);
  if (!m || Date.now() > Number(m[1])) return false;
  return safeEq(m[2], await hmac(env, "ark-admin|" + m[1]));
}
async function ensureSchema(env) {
  if (schemaReady || !env.DB) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, first_ts INTEGER, last_ts INTEGER, city TEXT, region TEXT, country TEXT, platform TEXT, ref_host TEXT, views INTEGER, dur INTEGER, engaged INTEGER, is_new INTEGER, device TEXT)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_first ON sessions(first_ts)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS fails (ts INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS chat (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, name TEXT, msg TEXT, cid TEXT, hidden INTEGER DEFAULT 0)")
  ]);
  schemaReady = true;
}

/* ---------- nosy neighbor news ---------- */
function decode(s) {
  return s.replace(/<!\[CDATA\[|\]\]>/g, "").replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}
async function rss(q) {
  const r = await fetch("https://news.google.com/rss/search?q=" + encodeURIComponent(q) + "&hl=en-US&gl=US&ceid=US:en", { headers: { "User-Agent": "Mozilla/5.0" } });
  if (!r.ok) return [];
  const x = await r.text();
  const items = [];
  const re = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = re.exec(x)) && items.length < 15) {
    const b = m[1];
    const g = (t) => { const mm = b.match(new RegExp("<" + t + "[^>]*>([\\s\\S]*?)</" + t + ">")); return mm ? decode(mm[1]).trim() : ""; };
    let title = g("title");
    const src = g("source");
    if (src && title.endsWith(" - " + src)) title = title.slice(0, -(src.length + 3));
    items.push({ title: title, link: g("link"), src: src, ts: Date.parse(g("pubDate")) || 0 });
  }
  return items;
}
async function neighbors(url) {
  const city = (url.searchParams.get("place") || "").slice(0, 40);
  const st = (url.searchParams.get("st") || "").toUpperCase();
  if (!/^[A-Za-z .'-]{2,40}$/.test(city) || !STATES[st]) return json({ error: "bad place" }, 400);
  const sn = STATES[st], base = city + " " + st;
  const Q = {
    stuck: base + ' flood (stranded OR trapped OR "water rescue" OR rescued OR "stuck in") when:3d',
    animals: base + ' flood (animals OR dog OR cat OR horses OR cattle OR alligator OR manatee) (rescue OR stranded OR floodwater) when:3d',
    missing: sn + ' (flood OR floodwaters OR "swept away") (missing OR "search for" OR searching) when:3d',
    deaths: sn + ' (flood OR flooding OR floodwaters OR "flash flood") (died OR killed OR dead OR drowned OR death OR fatal) when:3d'
  };
  const out = {};
  await Promise.all(Object.keys(Q).map(async (k) => {
    try {
      const seen = new Set();
      out[k] = (await rss(Q[k])).filter(i => FILTER[k].test(i.title) && RELEVANT.test(i.title) && !seen.has(i.title) && seen.add(i.title)).slice(0, 5);
    } catch (e) { out[k] = []; }
  }));
  return json({ ts: Date.now(), items: out }, 200, { "cache-control": "public, max-age=300" });
}

/* ---------- analytics ---------- */
async function track(request, env) {
  const none = () => new Response(null, { status: 204 });
  if (!env.DB) return none();
  const ua = request.headers.get("User-Agent") || "";
  if (BOT.test(ua)) return none();
  let b; try { b = await request.json(); } catch (e) { return none(); }
  const sid = String(b.sid || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 24);
  if (sid.length < 8) return none();
  await ensureSchema(env);
  const now = Date.now(), cf = request.cf || {};
  const city = String(cf.city || "Unknown").slice(0, 60);
  const region = String((cf.country === "US" ? cf.regionCode : cf.region) || "").slice(0, 40);
  const country = String(cf.country || "").slice(0, 3);
  if (b.t === "view") {
    const plat = PLATS.indexOf(b.plat) >= 0 ? b.plat : "Direct / Other";
    const host = String(b.host || "").slice(0, 80);
    const dev = /Mobi|Android|iPhone/i.test(ua) ? "Mobile" : "Desktop";
    await env.DB.prepare("INSERT INTO sessions (sid,first_ts,last_ts,city,region,country,platform,ref_host,views,dur,engaged,is_new,device) VALUES (?1,?2,?2,?3,?4,?5,?6,?7,1,0,0,?8,?9) ON CONFLICT(sid) DO UPDATE SET views=views+1, last_ts=?2, engaged=CASE WHEN views+1>=2 THEN 1 ELSE engaged END")
      .bind(sid, now, city, region, country, plat, host, b.nv ? 1 : 0, dev).run();
  } else if (b.t === "ping") {
    const dur = Math.max(0, Math.min(14400, parseInt(b.dur, 10) || 0));
    await env.DB.prepare("UPDATE sessions SET dur=MAX(dur,?2), last_ts=?3, engaged=CASE WHEN ?2>=10 OR views>=2 THEN 1 ELSE engaged END WHERE sid=?1").bind(sid, dur, now).run();
  }
  return none();
}

/* ---------- live chat ---------- */
async function chatGet(env, url) {
  if (!env.DB) return json({ nodb: true });
  await ensureSchema(env);
  const after = Math.max(0, parseInt(url.searchParams.get("after"), 10) || 0);
  const rows = after > 0
    ? (await env.DB.prepare("SELECT id, ts, name, msg FROM chat WHERE id>? AND hidden=0 ORDER BY id LIMIT 60").bind(after).all()).results
    : (await env.DB.prepare("SELECT id, ts, name, msg FROM (SELECT id, ts, name, msg FROM chat WHERE hidden=0 ORDER BY id DESC LIMIT 40) ORDER BY id").all()).results;
  const on = await env.DB.prepare("SELECT COUNT(*) n FROM sessions WHERE last_ts>=?").bind(Date.now() - 120000).first();
  return json({ msgs: rows || [], online: (on && on.n) || 0 });
}
async function chatPost(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  const ua = request.headers.get("User-Agent") || "";
  if (BOT.test(ua)) return json({ error: "no" }, 400);
  let b; try { b = await request.json(); } catch (e) { return json({ error: "bad" }, 400); }
  const name = String(b.name || "").replace(/[^\w \-'.]/g, "").trim().slice(0, 20);
  const msg = String(b.msg || "").replace(/[\u0000-\u001f<>]/g, " ").trim().slice(0, 200);
  const cid = String(b.cid || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 24);
  if (name.length < 2 || !msg || cid.length < 8) return json({ error: "bad" }, 400);
  if (/(https?:|www\.|\.com\b|\.net\b|\.ru\b|\.xyz\b|\.io\b|t\.me|bit\.ly)/i.test(msg)) return json({ error: "links" }, 400);
  await ensureSchema(env);
  const now = Date.now();
  const r = await env.DB.prepare("SELECT COUNT(*) n FROM chat WHERE cid=? AND ts>=?").bind(cid, now - 10000).first();
  if (r && r.n >= 3) return json({ error: "slow" }, 429);
  await env.DB.prepare("INSERT INTO chat (ts, name, msg, cid) VALUES (?,?,?,?)").bind(now, name, msg, cid).run();
  if (Math.random() < 0.02) await env.DB.prepare("DELETE FROM chat WHERE ts<?").bind(now - 7 * 86400000).run();
  return json({ ok: true });
}

/* ---------- admin ---------- */
async function login(request, env) {
  if (!env.ADMIN_PASSWORD_HASH) return json({ error: "not configured" }, 503);
  let b; try { b = await request.json(); } catch (e) { return json({ error: "bad" }, 400); }
  if (env.DB) {
    await ensureSchema(env);
    const r = await env.DB.prepare("SELECT COUNT(*) n FROM fails WHERE ts>=?").bind(Date.now() - 600000).first();
    if (r && r.n >= 8) return json({ error: "locked" }, 429);
  }
  const ok = safeEq(await sha256hex(String(b.password || "")), env.ADMIN_PASSWORD_HASH);
  if (!ok) {
    if (env.DB) await env.DB.prepare("INSERT INTO fails (ts) VALUES (?)").bind(Date.now()).run();
    await new Promise(r => setTimeout(r, 1000));
    return json({ error: "no" }, 401);
  }
  const exp = Date.now() + 12 * 3600 * 1000;
  return json({ ok: true, token: exp + "." + await hmac(env, "ark-admin|" + exp) });
}
async function stats(env, url) {
  if (!env.DB) return json({ nodb: true });
  await ensureSchema(env);
  const dd = Number(url.searchParams.get("days"));
  const days = [1, 7, 30, 90].indexOf(dd) >= 0 ? dd : 7;
  const off = Math.max(-50400, Math.min(50400, parseInt(url.searchParams.get("off"), 10) || 0));
  const since = Date.now() - days * 86400000;
  const fmt = days === 1 ? "%Y-%m-%d %H" : "%Y-%m-%d";
  const q = (sql, ...a) => env.DB.prepare(sql).bind(...a).all().then(r => r.results || []);
  const [tot, plat, loc, recent, series, live, mob, chat] = await Promise.all([
    q("SELECT COUNT(*) visits, COALESCE(SUM(views),0) views, COALESCE(SUM(dur),0) dur, COALESCE(SUM(engaged),0) eng, COALESCE(SUM(is_new),0) newv FROM sessions WHERE first_ts>=?", since),
    q("SELECT platform, COUNT(*) visits, SUM(views) views, SUM(engaged) eng FROM sessions WHERE first_ts>=? GROUP BY platform ORDER BY visits DESC", since),
    q("SELECT city, region, COUNT(*) visits, SUM(views) views FROM sessions WHERE first_ts>=? GROUP BY city, region ORDER BY visits DESC LIMIT 25", since),
    q("SELECT first_ts, city, region, platform, views, dur, engaged, device FROM sessions ORDER BY first_ts DESC LIMIT 25"),
    q("SELECT strftime('" + fmt + "', first_ts/1000 + ?2, 'unixepoch') d, COUNT(*) visits, SUM(views) views FROM sessions WHERE first_ts>=?1 GROUP BY d ORDER BY d", since, off),
    q("SELECT COUNT(*) n FROM sessions WHERE last_ts>=?", Date.now() - 120000),
    q("SELECT COUNT(*) n FROM sessions WHERE first_ts>=? AND device='Mobile'", since),
    q("SELECT id, ts, name, msg, hidden FROM chat ORDER BY id DESC LIMIT 30")
  ]);
  return json({ totals: tot[0] || {}, plat: plat, loc: loc, recent: recent, series: series, live: (live[0] || {}).n || 0, mobile: (mob[0] || {}).n || 0, chat: chat });
}

/* ---------- critical alert push (cron) ---------- */
async function checkAlerts(env) {
  const TOPIC = env.NTFY_TOPIC;
  if (!TOPIC) return;
  const r = await fetch("https://api.weather.gov/alerts/active?point=" + LAT + "," + LON, { headers: { "User-Agent": "noahs-ark-retruns-push", "Accept": "application/geo+json" } });
  if (!r.ok) return;
  const data = await r.json();
  const now = Date.now();
  const fresh = (data.features || []).map(f => f.properties).filter(p =>
    (CRIT.test(p.event || "") || p.severity === "Extreme") &&
    (now - Date.parse(p.sent || p.effective || 0)) <= 20 * 60 * 1000);
  if (!fresh.length) return;
  const seen = new Set();
  try {
    const h = await fetch("https://ntfy.sh/" + TOPIC + "/json?poll=1&since=30m");
    (await h.text()).split("\n").filter(Boolean).forEach(l => { try { (JSON.parse(l).tags || []).forEach(t => seen.add(t)); } catch (e) {} });
  } catch (e) {}
  for (const p of fresh) {
    const ref = "ref" + String(p.id || p.event).replace(/[^A-Za-z0-9]/g, "").slice(-14);
    if (seen.has(ref)) continue;
    await fetch("https://ntfy.sh/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ topic: TOPIC, title: "\u{1F6A8} " + p.event, message: ((p.headline || p.event) + " \u2014 " + (p.areaDesc || "")).slice(0, 400), priority: 5, tags: ["rotating_light", ref], click: env.DASH_URL || undefined })
    });
  }
}

/* ---------- router ---------- */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (p.startsWith("/api/")) {
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });
      let resp;
      try {
        if (p === "/api/neighbors") resp = await neighbors(url);
        else if (p === "/api/t" && request.method === "POST") resp = await track(request, env);
        else if (p === "/api/chat") resp = request.method === "POST" ? await chatPost(request, env) : await chatGet(env, url);
        else if (p === "/api/admin/login" && request.method === "POST") resp = await login(request, env);
        else if (p === "/api/admin/stats" || p === "/api/admin/chat/hide") {
          if (!(await authed(request, env))) resp = json({ error: "auth" }, 401);
          else if (p === "/api/admin/stats") resp = await stats(env, url);
          else {
            const b = await request.json().catch(() => ({}));
            if (env.DB && Number(b.id) > 0) await env.DB.prepare("UPDATE chat SET hidden=1 WHERE id=?").bind(Number(b.id)).run();
            resp = json({ ok: true });
          }
        } else resp = json({ error: "not found" }, 404);
      } catch (e) {
        resp = json({ error: "server" }, 500);
      }
      return withCors(resp, request, env);
    }
    return env.ASSETS.fetch(request);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(checkAlerts(env));
  }
};
