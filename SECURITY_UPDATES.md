# Security Updates

This note describes the security changes applied to the AT Space upload system
and how to verify them. All changes keep the app dependency-free and JSON-based.

## 1 & 2 — Brute-force protection + IP lockout (admin login)

The login in `admin.php` previously had **no** rate limiting: an attacker could
guess the password as many times as they liked. It now has a persistent,
per-IP lockout.

How it works:

- Failed logins are counted per client IP and stored in
  `uploads/login_security.json` (a flat JSON file, already blocked from the web
  by `.htaccess`).
- The store is **file-based, not session-based**, so an attacker cannot reset
  the counter by simply dropping their session cookie.
- After **3 wrong passwords** within a 15-minute window, that IP is **blocked
  for 15 minutes**. While blocked, the password is not even checked.
- A successful login clears the IP's failure record. Expired records are pruned
  automatically.
- The IP is stored only as a **salted SHA-256 hash**, never in clear text.
- `password_verify()` now runs on every attempt (against a dummy hash when the
  username is wrong) so response timing can't be used to discover the username.

Tunable settings near the top of `admin.php`:

```php
$maxLoginAttempts  = 3;     // wrong passwords before lockout (locks ON the 3rd)
$lockoutSeconds    = 900;   // ban length (15 min)
$attemptWindow     = 900;   // window failures are counted within
$ipHashSalt        = "...CHANGE-ME";  // change to any long random string
```

> Note: the lock triggers **on** the 3rd wrong password. If you want to allow a
> literal "more than 3" (i.e. lock on the 4th), set `$maxLoginAttempts = 4`.

> Behind a CDN/reverse proxy, the real visitor IP is in `X-Forwarded-For`.
> The code defaults to `REMOTE_ADDR` (safe — XFF can be spoofed). Only if you
> trust your proxy, change the login call to `alpha_client_ip(true)` and make
> sure the proxy overwrites that header.

## 3 & 4 — File type checking and allowed types

These were already strong and are retained. Each upload is validated by:

- An **extension allow-list** (`$allowedExtensions` in `index.php`):
  `jpg, jpeg, png, gif, webp, pdf, doc, docx, zip, txt`.
- A **MIME allow-list per extension** (`finfo`-detected, not the
  browser-supplied type).
- **Magic-byte checks** for PDF (`%PDF-`) and ZIP/DOCX (`PK..`) signatures.
- **Double-extension blocking** (e.g. `shell.php.jpg` is rejected).
- **Randomised server filenames**, so the original name can't control the path.

## 5 & 7 — Uploaded files can't be executed

`uploads/.htaccess` and `uploads/_deleted/.htaccess` now do two independent
things, so a file is harmless even if one layer fails:

1. **Deny all direct web access** (`Require all denied`, with an Apache 2.2
   fallback).
2. **Disable script execution** regardless of access: `RemoveHandler` /
   `SetHandler none` / `ForceType application/octet-stream` for every script
   type, plus `php_admin_flag engine off` (guarded by `<IfModule>` so it does
   not 500 under PHP-FPM/CGI), plus `Options -ExecCGI`.

The auto-generation of these files inside `admin.php` and `index.php` was also
updated to write this hardened version on fresh installs (the old version wrote
unguarded `Order/Deny` directives that can 500 on Apache 2.4).

## 6 — Verify direct URL access is blocked

`.htaccess` only works if the web server honours it. Verify on the live server
(while logged out):

```bash
# All of these MUST return 403 (or 404), never 200 with file contents:
curl -I https://your-domain/files/uploads/upload_data.json
curl -I https://your-domain/files/uploads/login_security.json
curl -I https://your-domain/files/uploads/<any-uploaded-file>

# Upload a harmless text file containing <?php echo 'X'; ?>, then request it.
# It must download/serve as text, NOT print "X".
```

If any returns the file contents:

- **Apache**: ensure `AllowOverride All` (not `None`) for the uploads directory
  so `.htaccess` is read.
- **Nginx** (ignores `.htaccess`): add to your server block:
  ```nginx
  location ^~ /files/uploads/ { deny all; return 403; }
  ```

## Quick local lint

```bash
php -l admin.php
php -l index.php
```
