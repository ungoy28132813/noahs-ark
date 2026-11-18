# NOAH'S ARK RETRUNS

Mobile-first live storm / flood / rainfall dashboard (NWS alerts, WPC Excessive Rainfall Outlook, rainfall in inches hour by hour, radar, FOX 35 video, nosy-neighbor gossip, live chat, admin stats).

- `site/` static front-end (deployed by Netlify; publish directory set in `netlify.toml`).
- `worker/` Cloudflare Worker backend (news, stats, chat, admin, alert push). Deploy with `npx wrangler deploy` after creating the D1 database and setting the `ADMIN_PASSWORD_HASH` secret.
- `window.ARK_API` at the top of `site/index.html` and `site/admin.html` points at the Worker URL.

Informational only. Follow official NWS warnings and call 911 in an emergency.
