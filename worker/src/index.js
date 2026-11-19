// NOAH'S ARK RETURNS - backend Worker
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
/* ---- shared chat word filter (same logic as the page) ---- */
var BADW=['nigger','nigga','faggot','tranny','retard','spic','chink','kike','gook','wetback','beaner','towelhead','raghead','fuck','shit','bitch','asshole','cunt','dick','pussy','whore','slut','rapist','kys'];
var BADP=[/kill\s*(your|ur)\s*self/,/go\s*(and\s*)?die/,/hang\s*(your|ur)\s*self/,/\b(i|we)\s*(will|ll|am going to|m gonna|gonna|wanna)\s*(kill|hurt|find|beat|shoot|rape)\s*(you|u)\b/,/\b(you|u)\s*(are|r|re)?\s*(so\s*)?(stupid|ugly|worthless|trash|pathetic|disgusting|dumb)\b/];
function normT(s){return String(s).toLowerCase().replace(/[01345@$!|]/g,function(c){return {'0':'o','1':'i','3':'e','4':'a','5':'s','@':'a','$':'s','!':'i','|':'i'}[c]}).replace(/\b[a-z](?:[\s.\-_*]+[a-z]\b)+/g,function(m){return m.replace(/[^a-z]/g,'')})}
function dd(s){return s.replace(/(.)\1+/g,'$1')}
function badWord(t){
  var a=normT(t),a2=dd(a),b=dd(a.replace(/[^a-z]/g,'')),i,w,w2;
  for(i=0;i<BADW.length;i++){w=BADW[i];w2=dd(w);
    if(new RegExp('(^|[^a-z])'+w+'(s|es|ed|ing|er|y|in)?($|[^a-z])').test(a))return true;
    if(new RegExp('(^|[^a-z])'+w2+'(s|es|ed|ing|er|y|in)?($|[^a-z])').test(a2))return true;
    if(w.length>=6&&b.indexOf(w2)>=0)return true}
  for(i=0;i<BADP.length;i++)if(BADP[i].test(a))return true;
  return false}
function privateInfo(t){t=String(t);return /@\w/.test(t)||/\b\d{3}[\s.\-]?\d{3}[\s.\-]?\d{4}\b/.test(t)||/\b\d{2,5}\s+[a-z]+\s+(st|street|ave|avenue|rd|road|dr|drive|ln|lane|blvd|ct|court|way)\b/i.test(t)}
/* ---- end filter ---- */
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
    env.DB.prepare("CREATE TABLE IF NOT EXISTS chat (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, name TEXT, msg TEXT, cid TEXT, hidden INTEGER DEFAULT 0, reply_to INTEGER, reply_name TEXT, reply_snip TEXT, room TEXT DEFAULT 'all')"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS squad_members (cid TEXT PRIMARY KEY, squad TEXT, city TEXT, st TEXT, ts INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS checkins (cid TEXT PRIMARY KEY, ts INTEGER, status TEXT, city TEXT, st TEXT, lat REAL, lon REAL, note TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, cid TEXT, name TEXT, city TEXT, st TEXT, cat TEXT, txt TEXT, img TEXT, vid TEXT, status TEXT DEFAULT 'pending', lat REAL, lon REAL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS polls (id INTEGER PRIMARY KEY AUTOINCREMENT, q TEXT, opts TEXT, ts INTEGER, closes INTEGER, truth INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS votes (poll_id INTEGER, cid TEXT, name TEXT, choice INTEGER, ts INTEGER, PRIMARY KEY (poll_id, cid))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS bans (cid TEXT PRIMARY KEY, name TEXT, ts INTEGER, reason TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS pins (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, name TEXT, msg TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS game_scores (cid TEXT PRIMARY KEY, name TEXT, best INTEGER, ts INTEGER, last INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS chat_reactions (msg_id INTEGER, cid TEXT, emoji TEXT, PRIMARY KEY (msg_id, cid))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS chat_reports (msg_id INTEGER, cid TEXT, PRIMARY KEY (msg_id, cid))"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS chat_strikes (cid TEXT, ts INTEGER)")
  ]);
  // older databases: add reply columns if missing (errors mean they already exist)
  for (const col of ["reply_to INTEGER", "reply_name TEXT", "reply_snip TEXT", "room TEXT DEFAULT 'all'"]) {
    try { await env.DB.prepare("ALTER TABLE chat ADD COLUMN " + col).run(); } catch (e) {}
  }
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
const REACTIONS = ["\u{1F44D}", "\u2764\uFE0F", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F64F}"];
async function chatGet(env, url) {
  if (!env.DB) return json({ nodb: true });
  await ensureSchema(env);
  const after = Math.max(0, parseInt(url.searchParams.get("after"), 10) || 0);
  const cid = String(url.searchParams.get("cid") || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 24);
  const room = roomOf(url.searchParams.get("room"));
  if (room !== "all") { // squad rooms are for members only
    const mem = cid.length >= 8 ? await env.DB.prepare("SELECT squad FROM squad_members WHERE cid=?").bind(cid).first() : null;
    if (!mem || mem.squad !== room) return json({ msgs: [], online: 0, reactions: {}, mine: {} });
  }
  const cols = "id, ts, name, msg, reply_name, reply_snip";
  const rows = after > 0
    ? (await env.DB.prepare("SELECT " + cols + " FROM chat WHERE id>? AND hidden=0 AND room=? ORDER BY id LIMIT 60").bind(after, room).all()).results
    : (await env.DB.prepare("SELECT " + cols + " FROM (SELECT " + cols + " FROM chat WHERE hidden=0 AND room=? ORDER BY id DESC LIMIT 40) ORDER BY id").bind(room).all()).results;
  const on = await env.DB.prepare("SELECT COUNT(*) n FROM sessions WHERE last_ts>=?").bind(Date.now() - 120000).first();
  // reactions for the 60 most recent messages (counts for everyone, plus this visitor's own pick)
  const lo = await env.DB.prepare("SELECT MIN(id) m FROM (SELECT id FROM chat WHERE hidden=0 AND room=? ORDER BY id DESC LIMIT 60)").bind(room).first();
  const minId = (lo && lo.m) || 0;
  const reactions = {}, mine = {};
  if (minId) {
    const rc = (await env.DB.prepare("SELECT msg_id, emoji, COUNT(*) n FROM chat_reactions WHERE msg_id>=? GROUP BY msg_id, emoji").bind(minId).all()).results || [];
    rc.forEach(r => { (reactions[r.msg_id] = reactions[r.msg_id] || {})[r.emoji] = r.n; });
    if (cid.length >= 8) {
      const mr = (await env.DB.prepare("SELECT msg_id, emoji FROM chat_reactions WHERE cid=? AND msg_id>=?").bind(cid, minId).all()).results || [];
      mr.forEach(r => { mine[r.msg_id] = r.emoji; });
    }
  }
  const pins = (await env.DB.prepare("SELECT id, name, msg FROM pins ORDER BY id DESC LIMIT 3").all()).results || [];
  return json({ msgs: rows || [], online: (on && on.n) || 0, reactions: reactions, mine: mine, pins: pins });
}
async function chatReact(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  let b; try { b = await request.json(); } catch (e) { return json({ error: "bad" }, 400); }
  const id = Number(b.id), cid = String(b.cid || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 24);
  if (!(id > 0) || cid.length < 8) return json({ error: "bad" }, 400);
  await ensureSchema(env);
  if (await isBanned(env, cid, "")) return json({ error: "banned" }, 403);
  if (b.emoji === null || b.emoji === undefined) {
    await env.DB.prepare("DELETE FROM chat_reactions WHERE msg_id=? AND cid=?").bind(id, cid).run();
    return json({ ok: true });
  }
  if (REACTIONS.indexOf(b.emoji) < 0) return json({ error: "bad" }, 400);
  const m = await env.DB.prepare("SELECT id FROM chat WHERE id=? AND hidden=0").bind(id).first();
  if (!m) return json({ error: "gone" }, 404);
  await env.DB.prepare("INSERT INTO chat_reactions (msg_id, cid, emoji) VALUES (?,?,?) ON CONFLICT(msg_id, cid) DO UPDATE SET emoji=excluded.emoji").bind(id, cid, b.emoji).run();
  return json({ ok: true });
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
  if (await isBanned(env, cid, name)) return json({ error: "banned" }, 403);
  // mute: 3 filtered messages in 10 minutes = 5 minute mute
  const st = await env.DB.prepare("SELECT COUNT(*) n, MAX(ts) last FROM chat_strikes WHERE cid=? AND ts>=?").bind(cid, now - 600000).first();
  if (st && st.n >= 3 && now - st.last < 300000) return json({ error: "muted" }, 429);
  if (badWord(name) || badWord(msg)) {
    await env.DB.prepare("INSERT INTO chat_strikes (cid, ts) VALUES (?,?)").bind(cid, now).run();
    return json({ error: "filtered" }, 400);
  }
  if (privateInfo(msg)) return json({ error: "privacy" }, 400);
  const room = roomOf(b.room);
  if (room !== "all") {
    const mem = await env.DB.prepare("SELECT squad FROM squad_members WHERE cid=?").bind(cid).first();
    if (!mem || mem.squad !== room) return json({ error: "not a member" }, 403);
  }
  const r = await env.DB.prepare("SELECT COUNT(*) n FROM chat WHERE cid=? AND ts>=?").bind(cid, now - 10000).first();
  if (r && r.n >= 3) return json({ error: "slow" }, 429);
  // optional reply to an earlier visible message (stores a short quote, never a private message)
  let rt = Number(b.reply_to) || 0, rn = null, rs = null;
  if (rt > 0) {
    const parent = await env.DB.prepare("SELECT name, msg FROM chat WHERE id=? AND hidden=0 AND room=?").bind(rt, room).first();
    if (parent) { rn = parent.name; rs = String(parent.msg).slice(0, 60); } else { rt = 0; }
  }
  await env.DB.prepare("INSERT INTO chat (ts, name, msg, cid, reply_to, reply_name, reply_snip, room) VALUES (?,?,?,?,?,?,?,?)").bind(now, name, msg, cid, rt || null, rn, rs, room).run();
  if (Math.random() < 0.02) await env.DB.prepare("DELETE FROM chat WHERE ts<?").bind(now - 7 * 86400000).run();
  return json({ ok: true });
}

async function chatReport(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  let b; try { b = await request.json(); } catch (e) { return json({ error: "bad" }, 400); }
  const id = Number(b.id), cid = String(b.cid || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 24);
  if (!(id > 0) || cid.length < 8) return json({ error: "bad" }, 400);
  await ensureSchema(env);
  await env.DB.prepare("INSERT OR IGNORE INTO chat_reports (msg_id, cid) VALUES (?,?)").bind(id, cid).run();
  const r = await env.DB.prepare("SELECT COUNT(*) n FROM chat_reports WHERE msg_id=?").bind(id).first();
  if (r && r.n >= 3) await env.DB.prepare("UPDATE chat SET hidden=1 WHERE id=?").bind(id).run(); // 3 different reports hide it automatically
  return json({ ok: true });
}


/* ---------- community: squads, check-ins, flood reports, polls ---------- */
const REPORT_CATS = ["road", "home", "water", "power", "other"];
const VIDEO_HOST = /^https:\/\/(www\.|m\.)?(youtube\.com|youtu\.be|facebook\.com|fb\.watch|tiktok\.com|instagram\.com)\//i;
function slugOf(city, st) { return (city + "-" + st).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
function cleanCid(v) { return String(v || "").replace(/[^A-Za-z0-9]/g, "").slice(0, 24); }
function okPlace(city, st) { return /^[A-Za-z .'-]{2,40}$/.test(city) && !!STATES[st]; }
function roundCoord(x) { return Math.round(Number(x) * 20) / 20; }
function roomOf(v) { v = String(v || "all"); return /^[a-z0-9-]{3,60}$/.test(v) ? v : "all"; }
async function readJson(request) { try { return await request.json(); } catch (e) { return null; } }
function safeText(s, max) { return String(s || "").replace(/[\u0000-\u001f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max); }

async function community(env, url) {
  if (!env.DB) return json({ nodb: true });
  await ensureSchema(env);
  const cid = cleanCid(url.searchParams.get("cid"));
  const now = Date.now();
  const q = (sql, ...a) => env.DB.prepare(sql).bind(...a).all().then(r => r.results || []);
  // first run: seed two starter polls so the section is never empty
  const pc = await env.DB.prepare("SELECT COUNT(*) n FROM polls").first();
  if (pc && pc.n === 0) {
    await env.DB.prepare("INSERT INTO polls (q, opts, ts, closes, truth) VALUES (?,?,?,?,NULL)").bind("Will the Indian River crest above flood stage this week?", JSON.stringify(["Yes", "No", "Not sure"]), now, now + 72 * 3600000).run();
    await env.DB.prepare("INSERT INTO polls (q, opts, ts, closes, truth) VALUES (?,?,?,?,NULL)").bind("How much rain will your area get through Sunday night?", JSON.stringify(["Under 3 in", "3 to 6 in", "Over 6 in"]), now, now + 72 * 3600000).run();
  }
  const [checkins, reports, polls, squads, board] = await Promise.all([
    q("SELECT status, city, st, lat, lon, ts, note FROM checkins WHERE ts>=? ORDER BY ts DESC LIMIT 300", now - 12 * 3600000),
    q("SELECT id, ts, city, st, cat, txt, vid, lat, lon, (img IS NOT NULL AND img<>'') has_img FROM reports WHERE status='ok' AND ts>=? ORDER BY ts DESC LIMIT 12", now - 24 * 3600000),
    q("SELECT id, q, opts, closes, truth FROM polls WHERE ts>=? ORDER BY id DESC LIMIT 6", now - 14 * 86400000),
    q("SELECT squad, MAX(city) city, MAX(st) st, COUNT(*) n FROM squad_members GROUP BY squad ORDER BY n DESC LIMIT 12"),
    q("SELECT MAX(v.name) name, SUM(CASE WHEN v.choice=p.truth THEN 1 ELSE 0 END) pts, COUNT(*) n FROM votes v JOIN polls p ON p.id=v.poll_id WHERE p.truth IS NOT NULL GROUP BY v.cid HAVING pts>0 ORDER BY pts DESC, n DESC LIMIT 10")
  ]);
  const ids = polls.map(p => Number(p.id)).filter(n => n > 0);
  const counts = {}, myVotes = {};
  if (ids.length) {
    (await q("SELECT poll_id, choice, COUNT(*) n FROM votes WHERE poll_id IN (" + ids.join(",") + ") GROUP BY poll_id, choice")).forEach(r => { (counts[r.poll_id] = counts[r.poll_id] || {})[r.choice] = r.n; });
    if (cid.length >= 8) (await q("SELECT poll_id, choice FROM votes WHERE cid=? AND poll_id IN (" + ids.join(",") + ")", cid)).forEach(r => { myVotes[r.poll_id] = r.choice; });
  }
  const outPolls = polls.map(p => { let o = []; try { o = JSON.parse(p.opts); } catch (e) {} return { id: p.id, q: p.q, opts: o, counts: o.map((_, i) => (counts[p.id] || {})[i] || 0), closes: p.closes, truth: p.truth }; });
  const mine = { squad: null, checkin: null, votes: myVotes };
  if (cid.length >= 8) {
    const s = await env.DB.prepare("SELECT squad, city, st FROM squad_members WHERE cid=?").bind(cid).first();
    if (s) { const n = await env.DB.prepare("SELECT COUNT(*) n FROM squad_members WHERE squad=?").bind(s.squad).first(); mine.squad = { squad: s.squad, city: s.city, st: s.st, n: (n && n.n) || 1 }; }
    const c = await env.DB.prepare("SELECT status FROM checkins WHERE cid=? AND ts>=?").bind(cid, now - 12 * 3600000).first();
    if (c) mine.checkin = c.status;
  }
  return json({ checkins: checkins, reports: reports, polls: outPolls, squads: squads, board: board, mine: mine });
}

async function checkin(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  const b = await readJson(request); if (!b) return json({ error: "bad" }, 400);
  const cid = cleanCid(b.cid); if (cid.length < 8) return json({ error: "bad" }, 400);
  await ensureSchema(env);
  if (b.status !== "clear" && await isBanned(env, cid, "")) return json({ error: "banned" }, 403);
  if (b.status === "clear") { await env.DB.prepare("DELETE FROM checkins WHERE cid=?").bind(cid).run(); return json({ ok: true }); }
  const status = b.status === "help" ? "help" : b.status === "safe" ? "safe" : null;
  const city = safeText(b.city, 40), st = String(b.st || "").toUpperCase();
  const lat = roundCoord(b.lat), lon = roundCoord(b.lon);
  if (!status || !okPlace(city, st) || !(lat > 17 && lat < 72) || !(lon > -170 && lon < -60)) return json({ error: "bad" }, 400);
  const note = safeText(b.note, 60);
  if (note && (badWord(note) || privateInfo(note) || /(https?:|www\.)/i.test(note))) return json({ error: "filtered" }, 400);
  const now = Date.now();
  const prev = await env.DB.prepare("SELECT ts FROM checkins WHERE cid=?").bind(cid).first();
  if (prev && now - prev.ts < 15000) return json({ error: "slow" }, 429);
  const burst = await env.DB.prepare("SELECT COUNT(*) n FROM checkins WHERE ts>=?").bind(now - 60000).first();
  if (burst && burst.n > 150) return json({ error: "busy" }, 429);
  await env.DB.prepare("INSERT INTO checkins (cid, ts, status, city, st, lat, lon, note) VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(cid) DO UPDATE SET ts=?2, status=?3, city=?4, st=?5, lat=?6, lon=?7, note=?8").bind(cid, now, status, city, st, lat, lon, note || null).run();
  if (Math.random() < 0.03) await env.DB.prepare("DELETE FROM checkins WHERE ts<?").bind(now - 36 * 3600000).run();
  return json({ ok: true });
}

async function squadJoin(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  const b = await readJson(request); if (!b) return json({ error: "bad" }, 400);
  const cid = cleanCid(b.cid); if (cid.length < 8) return json({ error: "bad" }, 400);
  await ensureSchema(env);
  if (b.leave) { await env.DB.prepare("DELETE FROM squad_members WHERE cid=?").bind(cid).run(); return json({ ok: true }); }
  const city = safeText(b.city, 40), st = String(b.st || "").toUpperCase();
  if (!okPlace(city, st)) return json({ error: "bad place" }, 400);
  const squad = slugOf(city, st);
  await env.DB.prepare("INSERT INTO squad_members (cid, squad, city, st, ts) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(cid) DO UPDATE SET squad=?2, city=?3, st=?4, ts=?5").bind(cid, squad, city, st, Date.now()).run();
  const n = await env.DB.prepare("SELECT COUNT(*) n FROM squad_members WHERE squad=?").bind(squad).first();
  return json({ ok: true, squad: squad, n: (n && n.n) || 1 });
}

async function reportPost(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  if (BOT.test(request.headers.get("User-Agent") || "")) return json({ error: "no" }, 400);
  const b = await readJson(request); if (!b) return json({ error: "bad" }, 400);
  const cid = cleanCid(b.cid); if (cid.length < 8) return json({ error: "bad" }, 400);
  const city = safeText(b.city, 40), st = String(b.st || "").toUpperCase();
  const cat = REPORT_CATS.indexOf(b.cat) >= 0 ? b.cat : null;
  const txt = safeText(b.txt, 280);
  const name = safeText(b.name, 20).replace(/[^\w \-'.]/g, "") || "Neighbor";
  const lat = roundCoord(b.lat), lon = roundCoord(b.lon);
  if (!okPlace(city, st) || !cat || txt.length < 10 || !(lat > 17 && lat < 72) || !(lon > -170 && lon < -60)) return json({ error: "bad" }, 400);
  if (badWord(txt) || badWord(name) || privateInfo(txt) || /(https?:|www\.)/i.test(txt)) return json({ error: "filtered" }, 400);
  let vid = null;
  if (b.vid) { vid = String(b.vid).trim().slice(0, 200); if (!VIDEO_HOST.test(vid)) return json({ error: "video host" }, 400); }
  let img = null;
  if (b.img) { img = String(b.img); if (img.length > 170000 || !/^data:image\/jpeg;base64,[A-Za-z0-9+\/=]+$/.test(img)) return json({ error: "photo" }, 400); }
  await ensureSchema(env);
  if (await isBanned(env, cid, name)) return json({ error: "banned" }, 403);
  const now = Date.now();
  const mine = await env.DB.prepare("SELECT COUNT(*) n FROM reports WHERE cid=? AND ts>=?").bind(cid, now - 3600000).first();
  if (mine && mine.n >= 3) return json({ error: "slow" }, 429);
  const pend = await env.DB.prepare("SELECT COUNT(*) n FROM reports WHERE status='pending'").first();
  if (pend && pend.n >= 100) return json({ error: "busy" }, 429);
  await env.DB.prepare("INSERT INTO reports (ts, cid, name, city, st, cat, txt, img, vid, status, lat, lon) VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)").bind(now, cid, name, city, st, cat, txt, img, vid, lat, lon).run();
  if (Math.random() < 0.03) await env.DB.prepare("DELETE FROM reports WHERE ts<?").bind(now - 30 * 86400000).run();
  return json({ ok: true, pending: true });
}

async function reportImg(env, url) {
  const id = Number(url.searchParams.get("id"));
  if (!env.DB || !(id > 0)) return new Response("not found", { status: 404 });
  const r = await env.DB.prepare("SELECT img FROM reports WHERE id=? AND status='ok'").bind(id).first();
  if (!r || !r.img) return new Response("not found", { status: 404 });
  const bin = atob(String(r.img).slice(String(r.img).indexOf(",") + 1));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return new Response(u8, { headers: { "content-type": "image/jpeg", "cache-control": "public, max-age=86400", "x-content-type-options": "nosniff" } });
}

async function pollVote(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  const b = await readJson(request); if (!b) return json({ error: "bad" }, 400);
  const cid = cleanCid(b.cid), pid = Number(b.poll), choice = Number(b.choice);
  if (cid.length < 8 || !(pid > 0) || !Number.isInteger(choice) || choice < 0) return json({ error: "bad" }, 400);
  await ensureSchema(env);
  if (await isBanned(env, cid, "")) return json({ error: "banned" }, 403);
  const p = await env.DB.prepare("SELECT id, opts, closes, truth FROM polls WHERE id=?").bind(pid).first();
  if (!p || p.truth !== null || Date.now() > p.closes) return json({ error: "closed" }, 409);
  let o = []; try { o = JSON.parse(p.opts); } catch (e) {}
  if (choice >= o.length) return json({ error: "bad" }, 400);
  let name = safeText(b.name, 20).replace(/[^\w \-'.]/g, "") || "Neighbor";
  if (badWord(name)) name = "Neighbor";
  await env.DB.prepare("INSERT OR IGNORE INTO votes (poll_id, cid, name, choice, ts) VALUES (?,?,?,?,?)").bind(pid, cid, name, choice, Date.now()).run();
  return json({ ok: true });
}

async function adminCommunity(p, request, env) {
  if (!env.DB) return json({ nodb: true });
  await ensureSchema(env);
  if (p === "/api/admin/reports") {
    const rows = (await env.DB.prepare("SELECT id, ts, name, city, st, cat, txt, img, vid FROM reports WHERE status='pending' ORDER BY id LIMIT 15").all()).results || [];
    return json({ pending: rows });
  }
  const b = await readJson(request); if (!b) return json({ error: "bad" }, 400);
  if (p === "/api/admin/report/decide") {
    const id = Number(b.id); if (!(id > 0)) return json({ error: "bad" }, 400);
    if (b.ok) await env.DB.prepare("UPDATE reports SET status='ok', ts=? WHERE id=?").bind(Date.now(), id).run();
    else await env.DB.prepare("UPDATE reports SET status='no', img=NULL WHERE id=?").bind(id).run();
    return json({ ok: true });
  }
  if (p === "/api/admin/poll/create") {
    const q = safeText(b.q, 120), opts = (Array.isArray(b.opts) ? b.opts : []).map(x => safeText(x, 40)).filter(Boolean).slice(0, 4);
    const hours = Math.max(1, Math.min(240, Number(b.hours) || 24));
    if (q.length < 8 || opts.length < 2) return json({ error: "bad" }, 400);
    const now = Date.now();
    await env.DB.prepare("INSERT INTO polls (q, opts, ts, closes, truth) VALUES (?,?,?,?,NULL)").bind(q, JSON.stringify(opts), now, now + hours * 3600000).run();
    return json({ ok: true });
  }
  if (p === "/api/admin/poll/resolve") {
    const id = Number(b.id), truth = Number(b.truth);
    if (!(id > 0) || !Number.isInteger(truth) || truth < 0) return json({ error: "bad" }, 400);
    await env.DB.prepare("UPDATE polls SET truth=? WHERE id=?").bind(truth, id).run();
    return json({ ok: true });
  }

  if (p === "/api/admin/ban") {
    let cid = cleanCid(b.cid), name = "";
    const id = Number(b.id);
    if (id > 0) { const m = await env.DB.prepare("SELECT cid, name FROM chat WHERE id=?").bind(id).first(); if (m) { cid = m.cid; name = m.name; } }
    if (cid.length < 8) return json({ error: "bad" }, 400);
    await env.DB.prepare("INSERT OR REPLACE INTO bans (cid, name, ts, reason) VALUES (?,?,?,?)").bind(cid, name, Date.now(), safeText(b.reason, 80) || null).run();
    await env.DB.prepare("UPDATE chat SET hidden=1 WHERE cid=?").bind(cid).run();
    await env.DB.prepare("DELETE FROM checkins WHERE cid=?").bind(cid).run();
    await env.DB.prepare("UPDATE reports SET status='no', img=NULL WHERE cid=? AND status='pending'").bind(cid).run();
    return json({ ok: true });
  }
  if (p === "/api/admin/unban") {
    const cid = cleanCid(b.cid); if (cid.length < 8) return json({ error: "bad" }, 400);
    await env.DB.prepare("DELETE FROM bans WHERE cid=?").bind(cid).run();
    return json({ ok: true });
  }
  if (p === "/api/admin/pin") {
    let name = "Owner", msg = safeText(b.text, 200);
    const id = Number(b.id);
    if (id > 0) { const m = await env.DB.prepare("SELECT name, msg FROM chat WHERE id=?").bind(id).first(); if (m) { name = m.name; msg = m.msg; } }
    if (msg.length < 2) return json({ error: "bad" }, 400);
    await env.DB.prepare("INSERT INTO pins (ts, name, msg) VALUES (?,?,?)").bind(Date.now(), name, msg).run();
    await env.DB.prepare("DELETE FROM pins WHERE id NOT IN (SELECT id FROM pins ORDER BY id DESC LIMIT 3)").run();
    return json({ ok: true });
  }
  if (p === "/api/admin/unpin") {
    const id = Number(b.id); if (!(id > 0)) return json({ error: "bad" }, 400);
    await env.DB.prepare("DELETE FROM pins WHERE id=?").bind(id).run();
    return json({ ok: true });
  }
  return json({ error: "not found" }, 404);
}


/* ---------- moderation extras: bans ---------- */
async function isBanned(env, cid, name) {
  const a = await env.DB.prepare("SELECT 1 x FROM bans WHERE cid=?").bind(cid).first();
  if (a) return true;
  if (name) { const b = await env.DB.prepare("SELECT 1 x FROM bans WHERE lower(name)=lower(?)").bind(name).first(); if (b) return true; }
  return false;
}

/* ---------- mini game: Chicken Crossing leaderboard ---------- */
async function gameBoard(env, url) {
  if (!env.DB) return json({ nodb: true });
  await ensureSchema(env);
  const cid = cleanCid(url.searchParams.get("cid"));
  const board = (await env.DB.prepare("SELECT name, best FROM game_scores ORDER BY best DESC, ts ASC LIMIT 10").all()).results || [];
  let mine = null;
  if (cid.length >= 8) {
    const m = await env.DB.prepare("SELECT best FROM game_scores WHERE cid=?").bind(cid).first();
    if (m) { const r = await env.DB.prepare("SELECT COUNT(*) n FROM game_scores WHERE best>?").bind(m.best).first(); mine = { best: m.best, rank: ((r && r.n) || 0) + 1 }; }
  }
  return json({ board: board, mine: mine });
}
async function gameScore(request, env) {
  if (!env.DB) return json({ error: "nodb" }, 503);
  if (BOT.test(request.headers.get("User-Agent") || "")) return json({ error: "no" }, 400);
  const b = await readJson(request); if (!b) return json({ error: "bad" }, 400);
  const cid = cleanCid(b.cid), score = Math.floor(Number(b.score)), secs = Number(b.secs);
  const name = safeText(b.name, 20).replace(/[^\w \-'.]/g, "");
  if (cid.length < 8 || name.length < 2 || !(score >= 1 && score <= 500) || !(secs > 0)) return json({ error: "bad" }, 400);
  if (score > secs * 4 + 3) return json({ error: "bad" }, 400); // faster than humanly possible
  if (badWord(name)) return json({ error: "filtered" }, 400);
  await ensureSchema(env);
  if (await isBanned(env, cid, name)) return json({ error: "banned" }, 403);
  const now = Date.now();
  const prev = await env.DB.prepare("SELECT last FROM game_scores WHERE cid=?").bind(cid).first();
  if (prev && now - prev.last < 4000) return json({ error: "slow" }, 429);
  await env.DB.prepare("INSERT INTO game_scores (cid, name, best, ts, last) VALUES (?1,?2,?3,?4,?4) ON CONFLICT(cid) DO UPDATE SET name=?2, ts=CASE WHEN ?3>best THEN ?4 ELSE ts END, best=MAX(best, ?3), last=?4").bind(cid, name, score, now).run();
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
  const [tot, plat, loc, recent, series, live, mob, chat, pins, bans] = await Promise.all([
    q("SELECT COUNT(*) visits, COALESCE(SUM(views),0) views, COALESCE(SUM(dur),0) dur, COALESCE(SUM(engaged),0) eng, COALESCE(SUM(is_new),0) newv FROM sessions WHERE first_ts>=?", since),
    q("SELECT platform, COUNT(*) visits, SUM(views) views, SUM(engaged) eng FROM sessions WHERE first_ts>=? GROUP BY platform ORDER BY visits DESC", since),
    q("SELECT city, region, COUNT(*) visits, SUM(views) views FROM sessions WHERE first_ts>=? GROUP BY city, region ORDER BY visits DESC LIMIT 25", since),
    q("SELECT first_ts, city, region, platform, views, dur, engaged, device FROM sessions ORDER BY first_ts DESC LIMIT 25"),
    q("SELECT strftime('" + fmt + "', first_ts/1000 + ?2, 'unixepoch') d, COUNT(*) visits, SUM(views) views FROM sessions WHERE first_ts>=?1 GROUP BY d ORDER BY d", since, off),
    q("SELECT COUNT(*) n FROM sessions WHERE last_ts>=?", Date.now() - 120000),
    q("SELECT COUNT(*) n FROM sessions WHERE first_ts>=? AND device='Mobile'", since),
    q("SELECT id, ts, name, msg, hidden, room, (SELECT COUNT(*) FROM chat_reports r WHERE r.msg_id=chat.id) reports, (SELECT COUNT(*) FROM bans b WHERE b.cid=chat.cid) banned FROM chat ORDER BY id DESC LIMIT 30"),
    q("SELECT id, ts, name, msg FROM pins ORDER BY id DESC LIMIT 5"),
    q("SELECT cid, name, ts FROM bans ORDER BY ts DESC LIMIT 30")
  ]);
  return json({ totals: tot[0] || {}, plat: plat, loc: loc, recent: recent, series: series, live: (live[0] || {}).n || 0, mobile: (mob[0] || {}).n || 0, chat: chat, pins: pins, bans: bans });
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
        else if (p === "/api/game/board") resp = await gameBoard(env, url);
        else if (p === "/api/game/score" && request.method === "POST") resp = await gameScore(request, env);
        else if (p === "/api/community") resp = await community(env, url);
        else if (p === "/api/checkin" && request.method === "POST") resp = await checkin(request, env);
        else if (p === "/api/squad/join" && request.method === "POST") resp = await squadJoin(request, env);
        else if (p === "/api/report" && request.method === "POST") resp = await reportPost(request, env);
        else if (p === "/api/report/img") resp = await reportImg(env, url);
        else if (p === "/api/poll/vote" && request.method === "POST") resp = await pollVote(request, env);
        else if (/^\/api\/admin\/(reports|report\/decide|poll\/create|poll\/resolve|ban|unban|pin|unpin)$/.test(p)) {
          if (!(await authed(request, env))) resp = json({ error: "auth" }, 401);
          else resp = await adminCommunity(p, request, env);
        }
        else if (p === "/api/chat/report" && request.method === "POST") resp = await chatReport(request, env);
        else if (p === "/api/chat/react" && request.method === "POST") resp = await chatReact(request, env);
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
