# NOAH'S ARK RETURNS: project handoff

## Files
- MASTER_PROMPT.md: the full instructions to give your coding assistant.
- project-bundle.json: every source file in one JSON (paths -> contents).
- site/index.html and site/admin.html: also delivered separately so you can open them in a browser.

## Unpack the bundle (Windows, macOS or Linux with Python installed)
Put project-bundle.json in an empty folder, open a terminal there and run:

python3 -c "import json,os;d=json.load(open('project-bundle.json',encoding='utf8'));[(os.makedirs(os.path.dirname(p) or '.',exist_ok=True),open(p,'w',encoding='utf8').write(c)) for p,c in d['files'].items()]"

(On Windows use `python` instead of `python3`.) You get: site/, worker/, netlify.toml, MASTER_PROMPT.md, README.md.

## Fastest way to see it live
1. Cloudflare: cd worker, npx wrangler login, npx wrangler d1 create ark-analytics (paste the id into wrangler.toml), npx wrangler secret put ADMIN_PASSWORD_HASH (the SHA-256 hex of your admin password; never put it in a file or in GitHub), npx wrangler deploy.
2. Netlify: edit window.ARK_API in site/index.html and site/admin.html to your Worker URL, add your Netlify URL to ALLOWED_ORIGINS in wrangler.toml, redeploy the Worker, then drop the site folder on Netlify's "Drop files to deploy" box.
3. Admin page: your site URL followed by /admin.

## Secrets
The admin password is stored only as a SHA-256 hash. To change it, compute a new SHA-256 hex of the new password and run wrangler secret put ADMIN_PASSWORD_HASH again. The ntfy topic works like a password for push messages: set it with npx wrangler secret put NTFY_TOPIC, never in a file.
