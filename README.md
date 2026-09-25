# Security Pack — Language & Currency (GeoIP) notes

The "GeoIP Language & Currency" feature (Setup > Addon Modules > Security
Pack > Language & Currency, once enabled under the main Settings tab) can
resolve a visitor's country two ways:

1. **MaxMind GeoLite2-Country.mmdb (preferred)** — a local binary database
   you upload once from the module's admin page. Lookups are instant, no
   external network calls, no rate limits.
2. **Free curl-based providers (fallback)** — freeipapi.com, geojs.io,
   ipapi.co, tried in turn. Used automatically whenever no `.mmdb` is
   uploaded, or the MaxMind lookup misses.

Every resolved IP (from either source) is cached in the
`nnm_security_pack_geo_cache` table for the configured number of days, so
a given visitor is only ever looked up once.

## Getting a free GeoLite2-Country.mmdb

1. Create a free MaxMind account and license key at
   <https://www.maxmind.com/en/geolite2/signup>.
2. Download `GeoLite2-Country.mmdb` (the `.tar.gz`/`.zip` distribution
   contains it).
3. Upload it from **Security Pack > Language & Currency > GeoIP Database
   Status > Upload / Replace Database**. The module validates the file is
   a real MaxMind DB before accepting it.

## Keeping it up to date automatically

MaxMind updates GeoLite2 databases roughly weekly. To automate refreshing
it, use MaxMind's official `geoipupdate` tool
(<https://github.com/maxmind/geoipupdate>) on your server and point its
output at:

```
modules/addons/security_pack/core/data/GeoLite2-Country.mmdb
```

Example cron entry (adjust paths for your server) once `geoipupdate` is
configured with your license key:

```cron
0 4 * * 3 /usr/bin/geoipupdate -f /etc/GeoIP.conf -d /home/ishroot/webapps/mcs/public/modules/addons/security_pack/core/data
```

The `core/data/` folder ships with a `.htaccess` denying direct web access
to the `.mmdb` file (Apache/LiteSpeed hosts) — no secrets are in the file,
but there's no reason to serve it publicly either.

## Where things live

- `core/data/GeoLite2-Country.mmdb` — the uploaded database (not included;
  you provide your own, see above).
- `lib/MaxMindDb/Reader.php` — a small, dependency-free reader for the
  open MaxMind DB binary format (no Composer packages required).
- `core/geoip_lang_currency.php` — applies the resolved
  language/currency to the visitor's session and renders the notice
  banner.
- `lib/Admin/LangCurrencyController.php` — the admin management page
  (database status/upload, test-a-lookup, default fallback, per-country
  rules).
