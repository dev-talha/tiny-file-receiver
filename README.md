# AT Space — Secure Tiny File Receiver

A lightweight, dependency‑free PHP application for accepting public file uploads and reviewing them through a protected admin dashboard. Built for **PHP 8.3**, it uses flat **JSON metadata** (no database) and a strict, JavaScript‑free security model.

---

## Features

- **Public upload page** (`index.php`) — email‑gated uploads with extension whitelist, MIME verification, randomized server filenames, and double‑extension script blocking.
- **Secure admin dashboard** (`admin.php`) — login‑protected review of uploaded files with search, type/status/date filters, pagination, and per‑file approval.
- **Soft delete** — files are moved to `uploads/_deleted/` and flagged in metadata instead of being permanently removed; the active dashboard hides them and shows a deleted count.
- **Protected file serving** — uploads are never served directly from the web; the admin views/downloads them through `admin.php` with safe inline rendering for images/PDF/TXT and forced download for everything else.
- **No JavaScript required** — the delete confirmation modal is pure CSS (`:target`), so a strict `script-src` Content‑Security‑Policy can be enforced.
- **Mobile‑responsive admin UI** — single‑column layout, top‑right navigation bar with Logout, and a table that collapses into cards on small screens.

---

## Tech stack

| Area        | Choice                                             |
| ----------- | -------------------------------------------------- |
| Language    | PHP 8.3                                            |
| Storage     | Flat JSON (`uploads/upload_data.json`) — no DB     |
| Frontend    | Server‑rendered HTML + inline CSS, no JS framework |
| Web server  | Apache / LiteSpeed (`.htaccess`) — Nginx supported with config (see below) |
| Dependencies| None                                               |

---

## Project structure

```
files/
├── index.php                 # Public upload page
├── admin.php                 # Admin dashboard (login, review, approve, soft delete)
├── logo.svg                  # Brand asset
├── README.md                 # This file
└── uploads/
    ├── .htaccess             # Denies direct web access to the whole folder
    ├── index.html            # Empty index (anti directory-listing)
    ├── upload_data.json      # File metadata (server-side only — never web-served)
    └── _deleted/
        ├── .htaccess         # Denies direct web access to soft-deleted files
        └── index.html        # Empty index
```

> The web server must be able to write to `uploads/` and `uploads/_deleted/`.

---

## Requirements

- PHP 8.3 (CLI/FPM/module all fine)
- Apache or LiteSpeed with `mod_headers` enabled and **`AllowOverride`** permitting `.htaccess`, **or** Nginx with the equivalent rules below
- A writable `uploads/` directory (and `uploads/_deleted/`)

---

## Installation

1. Copy the contents of `files/` into your web root (or a subdirectory).
2. Ensure the upload directories are writable by the web server user:
   ```bash
   chmod 755 uploads uploads/_deleted
   ```
3. Confirm the `.htaccess` files are present in `uploads/` and `uploads/_deleted/`.
4. Set your admin credentials (see **Configuration**).
5. Visit `admin.php` to log in, and `index.php` for the public upload form.

---

## Configuration

### Admin credentials

Credentials are defined near the top of `admin.php`:

```php
$adminUser      = "your-admin-username";          // <-- replace
$adminPassHash  = "your-bcrypt-password-hash";     // <-- replace (see below)
```

> **Do not commit real credentials.** Keep the username and password hash out of
> version control (use environment variables or a local, git‑ignored config
> include in production).

Generate a bcrypt hash for your chosen password:

```bash
php -r 'echo password_hash("your-secure-password", PASSWORD_BCRYPT, ["cost" => 12]), PHP_EOL;'
```

Paste the resulting hash into `$adminPassHash`. The app verifies logins with
`password_verify()`, so the plaintext password is never stored.

### Upload limits / allowed types

Defined in `index.php`:

```php
$maxSize           = 20 * 1024 * 1024; // 20 MB
$allowedExtensions = ["jpg","jpeg","png","gif","webp","pdf","doc","docx","zip","txt"];
```

Adjust as needed; MIME types are validated against an allow‑list per extension.

---

## Security model

- **Session hardening** — `HttpOnly`, `SameSite=Lax`, and `Secure` (when served over HTTPS) cookies; session ID regenerated on login.
- **CSRF protection** — all state‑changing POST actions (login, approvals, soft delete) require a per‑session token compared with `hash_equals()`.
- **Output escaping** — all dynamic output passes through `htmlspecialchars()`.
- **Path‑traversal protection** — requested filenames are reduced to `basename()` and resolved with `realpath()`, then confirmed to live inside the uploads directory.
- **No executable serving** — script/markup extensions (`.php`, `.phtml`, `.phar`, `.html`, `.js`, `.svg`, `.json`, etc.) are blocked from the view/download endpoint.
- **Security headers** — `X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and a strict `Content-Security-Policy` (admin uses `script-src 'none'`).
- **Direct‑access denial** — the `uploads/` folder denies all direct web requests; the metadata file `upload_data.json` is additionally protected by an explicit `FilesMatch` rule. It is read only server‑side by PHP.

### Protecting `uploads/upload_data.json` (and the uploads folder)

`uploads/.htaccess` applies a default deny plus an explicit rule for sensitive
file types (works on Apache 2.4/LiteSpeed and Apache 2.2):

```apache
Options -Indexes

<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from all
</IfModule>

<FilesMatch "(?i)\.(json|php|phtml|php[0-9]|phar|html?|js|svg|cgi|pl|py|sh|bash)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>
```

**A `.htaccess` only works if the server honors it.** If the metadata file is
still reachable in a browser:

- **Apache** — ensure `AllowOverride` is not `None` for the directory:
  ```apache
  <Directory "/path/to/files/uploads">
      AllowOverride All
  </Directory>
  ```
- **Nginx** (ignores `.htaccess`) — add to your server block:
  ```nginx
  location ^~ /files/uploads/ {
      deny all;
      return 403;
  }
  ```

**Verify** (while logged out):

```bash
curl -I https://your-domain.example/files/uploads/upload_data.json
# Expect: HTTP/1.1 403 Forbidden
```

---

## Admin dashboard usage

1. Go to `admin.php` and log in.
2. Use **Search & Filters** to find files by name/email, type, approval status, or date range.
3. Toggle **Approve** checkboxes and click **Save Approval Changes** to update statuses.
4. Use the row actions to **View** (inline for image/PDF/TXT), **Download**, or **Soft Delete** a file.
5. Soft‑deleted files move to `uploads/_deleted/` and are counted under **Deleted**.
6. **Logout** is in the top‑right navigation bar.

---

## Development

Run locally with PHP's built‑in server:

```bash
php -S 127.0.0.1:8000 -t files
# Public upload:  http://127.0.0.1:8000/index.php
# Admin:          http://127.0.0.1:8000/admin.php
```

> The built‑in server does **not** process `.htaccess`. Test direct‑access
> protection on a real Apache/LiteSpeed/Nginx environment.

Lint before committing:

```bash
php -l files/admin.php
php -l files/index.php
```

---

## Changelog (recent)

- **Admin UI update** — removed the sidebar; moved Logout to a top‑right navigation bar; made the dashboard fully mobile‑responsive (no backend/logic changes).
- **Security enhancement** — hardened `uploads/.htaccess` with layered deny rules and an explicit `FilesMatch` for `upload_data.json`.

---

## License

Add your license here (e.g. MIT). Replace this section before publishing.
