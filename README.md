[build]
  publish = "site"

[[redirects]]
  from = "/admin"
  to = "/admin.html"
  status = 200

[[headers]]
  for = "/sw.js"
  [headers.values]
    Cache-Control = "no-cache"
