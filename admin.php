<?php
/*
    PHP 8.3 Compatible


    AT Space PHP 8.3 Secure Professional Admin Dashboard - Mobile Fixed + Approval Save Fix
    Public upload page is separate.

    Login:
    Username: demo
    Password: demo@999

    Security:
    - Secure session cookie settings
    - Password hash verification
    - CSRF protection
    - Output escaping
    - Path traversal protection
    - Admin-only file view/download
    - Safe inline view only for image/pdf/txt
    - Forced download for other files
    - Security headers
*/

$https = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off");
session_set_cookie_params([
    "lifetime" => 0,
    "path" => "/",
    "domain" => "",
    "secure" => $https,
    "httponly" => true,
    "samesite" => "Lax"
]);
session_start();

header("X-Frame-Options: SAMEORIGIN");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: same-origin");
header("Permissions-Policy: geolocation=(), camera=(), microphone=()");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'");

$adminUser = "admin";
$adminPassHash = '$2y$12$24ijWci34/UqUv/qXhzBo.KeQiacg9Behzx/CCTW6OddzGFohXyu6'; // admin@999

$uploadDir = __DIR__ . "/uploads/";
$metadataFile = $uploadDir . "upload_data.json";
$oldApprovalFile = $uploadDir . "approvals.json";

/*
    -----------------------------------------------------------------------
    Login brute-force protection / IP lockout
    -----------------------------------------------------------------------
    - $maxLoginAttempts wrong passwords from one IP within $attemptWindow
      seconds triggers a lockout of $lockoutSeconds.
    - State is stored in a flat JSON file inside uploads/ (already denied to
      the web by .htaccess) so the limit survives across sessions and
      browsers -- a session-only limit is trivially bypassed by dropping the
      cookie.
    - The IP is stored only as a salted SHA-256 hash, never in clear text.
    -----------------------------------------------------------------------
*/
$maxLoginAttempts  = 3;     // wrong passwords allowed before lockout
$lockoutSeconds    = 900;   // 15 minute ban once the limit is hit
$attemptWindow     = 900;   // failures are counted within this rolling window
$loginSecurityFile = $uploadDir . "login_security.json";

// Change this to any long random string. It only salts the stored IP hashes.
$ipHashSalt = "alpha-net-login-security-salt-CHANGE-ME";

$message = "";
$messageType = "";

if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

function alpha_is_logged_in() {
    return isset($_SESSION["admin_logged_in"]) && $_SESSION["admin_logged_in"] === true;
}

function alpha_clean($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, "UTF-8");
}

function alpha_format_size($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . " GB";
    }

    if ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . " MB";
    }

    if ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . " KB";
    }

    return $bytes . " B";
}

function alpha_file_type_group($ext) {
    $ext = strtolower($ext);

    if (in_array($ext, ["jpg", "jpeg", "png", "gif", "webp"], true)) {
        return "image";
    }

    if ($ext === "pdf") {
        return "pdf";
    }

    if (in_array($ext, ["doc", "docx"], true)) {
        return "document";
    }

    if ($ext === "zip") {
        return "zip";
    }

    if ($ext === "txt") {
        return "text";
    }

    return "other";
}

function alpha_file_badge($ext) {
    $group = alpha_file_type_group($ext);

    if ($group === "image") {
        return "IMG";
    }

    if ($group === "pdf") {
        return "PDF";
    }

    if ($group === "document") {
        return "DOC";
    }

    if ($group === "zip") {
        return "ZIP";
    }

    if ($group === "text") {
        return "TXT";
    }

    return "FILE";
}

function alpha_short_file_name($fileName, $maxLength = 36) {
    if (strlen($fileName) <= $maxLength) {
        return $fileName;
    }

    $ext = pathinfo($fileName, PATHINFO_EXTENSION);
    $base = pathinfo($fileName, PATHINFO_FILENAME);

    if ($ext !== "") {
        $ending = substr($base, -13) . "." . $ext;
    } else {
        $ending = substr($fileName, -16);
    }

    $startLength = $maxLength - strlen($ending) - 5;

    if ($startLength < 8) {
        $startLength = 8;
    }

    return substr($fileName, 0, $startLength) . "....." . $ending;
}

function alpha_load_json($filePath) {
    if (!file_exists($filePath)) {
        return [];
    }

    $json = file_get_contents($filePath);
    $data = json_decode($json, true);

    return is_array($data) ? $data : [];
}

function alpha_save_json($filePath, $data) {
    $json = json_encode($data, JSON_PRETTY_PRINT);

    if ($json === false) {
        return false;
    }

    return file_put_contents($filePath, $json, LOCK_EX) !== false;
}

/*
    -----------------------------------------------------------------------
    Login security helpers (brute-force lockout by IP)
    -----------------------------------------------------------------------
*/

// Best-effort client IP. By default we trust only REMOTE_ADDR, because
// X-Forwarded-For can be spoofed by the client to either evade a ban or
// frame another address. If you run behind a known reverse proxy/CDN,
// set $trustProxy = true AND make sure the proxy overwrites the header.
function alpha_client_ip($trustProxy = false) {
    if ($trustProxy && !empty($_SERVER["HTTP_X_FORWARDED_FOR"])) {
        $parts = explode(",", $_SERVER["HTTP_X_FORWARDED_FOR"]);
        $candidate = trim($parts[0]);
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }
    $ip = $_SERVER["REMOTE_ADDR"] ?? "0.0.0.0";
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : "0.0.0.0";
}

function alpha_ip_key($ip, $salt) {
    return hash("sha256", $ip . "|" . $salt);
}

// Load the lockout store and drop entries that are fully expired.
function alpha_load_login_security($path, $attemptWindow, $now) {
    $data = alpha_load_json($path);
    $changed = false;

    foreach ($data as $key => $rec) {
        if (!is_array($rec)) {
            unset($data[$key]);
            $changed = true;
            continue;
        }
        $lockedUntil = (int)($rec["locked_until"] ?? 0);
        $lastFail    = (int)($rec["last_fail"] ?? 0);

        // Forget the record once the lock has expired and no recent failures.
        if ($lockedUntil < $now && ($now - $lastFail) > $attemptWindow) {
            unset($data[$key]);
            $changed = true;
        }
    }

    if ($changed) {
        alpha_save_json($path, $data);
    }

    return $data;
}

// Returns seconds remaining on an active lockout, or 0 if not locked.
function alpha_login_lock_remaining($store, $ipKey, $now) {
    $lockedUntil = (int)($store[$ipKey]["locked_until"] ?? 0);
    return ($lockedUntil > $now) ? ($lockedUntil - $now) : 0;
}

// Record a failed login. Returns the updated store. Applies a lockout once
// the failure count within the rolling window reaches $maxLoginAttempts.
function alpha_register_failed_login($store, $ipKey, $now, $maxLoginAttempts, $attemptWindow, $lockoutSeconds) {
    $rec = is_array($store[$ipKey] ?? null) ? $store[$ipKey] : [];

    $firstFail = (int)($rec["first_fail"] ?? 0);
    $fails     = (int)($rec["fails"] ?? 0);

    // Reset the counter if the previous failures are outside the window.
    if ($firstFail === 0 || ($now - $firstFail) > $attemptWindow) {
        $firstFail = $now;
        $fails = 0;
    }

    $fails++;

    $rec["fails"]      = $fails;
    $rec["first_fail"] = $firstFail;
    $rec["last_fail"]  = $now;

    if ($fails >= $maxLoginAttempts) {
        $rec["locked_until"] = $now + $lockoutSeconds;
    }

    $store[$ipKey] = $rec;
    return $store;
}

function alpha_human_duration($seconds) {
    $seconds = max(0, (int)$seconds);
    if ($seconds >= 60) {
        $mins = (int)ceil($seconds / 60);
        return $mins . " minute" . ($mins === 1 ? "" : "s");
    }
    return $seconds . " second" . ($seconds === 1 ? "" : "s");
}

function alpha_get_file_path($fileName, $uploadDir) {
    $safeName = basename($fileName);
    $realUploadDir = realpath($uploadDir);

    if ($realUploadDir === false) {
        return false;
    }

    $filePath = realpath($realUploadDir . DIRECTORY_SEPARATOR . $safeName);

    if ($filePath === false || !is_file($filePath)) {
        return false;
    }

    if (strpos($filePath, $realUploadDir) !== 0) {
        return false;
    }

    $blocked = ["htaccess", "json", "php", "php3", "php4", "php5", "php7", "phtml", "phar", "html", "htm", "js", "svg", "cgi", "pl", "py", "sh", "bash"];
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

    if (in_array($ext, $blocked, true)) {
        return false;
    }

    return $filePath;
}

function alpha_detect_mime($path) {
    if (function_exists("finfo_open")) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $mime = finfo_file($finfo, $path);
            finfo_close($finfo);
            return $mime ?: "application/octet-stream";
        }
    }

    if (function_exists("mime_content_type")) {
        return mime_content_type($path);
    }

    return "application/octet-stream";
}

function alpha_page_link($page) {
    $query = $_GET;
    unset($query["view"], $query["download"], $query["logout"]);
    $query["page"] = $page;
    return "?" . http_build_query($query);
}

function alpha_prepare_upload_folder($uploadDir) {
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    $indexPath = $uploadDir . "index.html";
    if (!file_exists($indexPath)) {
        file_put_contents($indexPath, "");
    }

    $htaccessPath = $uploadDir . ".htaccess";
    $htaccess = <<<'HTACCESS'
# AT Space upload folder protection
# Save this file as: uploads/.htaccess
# Uploaded files must be served through admin.php only -- never directly
# over the web, and never executed.

Options -Indexes -ExecCGI

# Default deny: block direct web access to everything in this folder.
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from all
</IfModule>

# Defense-in-depth: never let anything here run as a script.
RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8 .phps .phar .pl .py .pyc .cgi .sh .bash .jsp .asp .aspx
RemoveType    .php .phtml .php3 .php4 .php5 .php7 .php8 .phps .phar .pl .py .cgi .sh

<FilesMatch "(?i)\.(php|phtml|php[0-9]|phps|phar|pl|py|pyc|cgi|sh|bash|jsp|asp|aspx|exe|com|bat|cmd)$">
    SetHandler none
    ForceType application/octet-stream
</FilesMatch>

<IfModule mod_php.c>
    php_admin_flag engine off
</IfModule>
<IfModule mod_php8.c>
    php_admin_flag engine off
</IfModule>
<IfModule mod_php7.c>
    php_admin_flag engine off
</IfModule>

<FilesMatch "(?i)\.(json|php|phtml|php[0-9]|phps|phar|html?|js|mjs|svg|cgi|pl|py|sh|bash)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>

<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set Content-Security-Policy "sandbox"
    Header set Content-Disposition "attachment"
</IfModule>
HTACCESS;

    if (!file_exists($htaccessPath)) {
        file_put_contents($htaccessPath, $htaccess);
    }
}

alpha_prepare_upload_folder($uploadDir);

// Logout
if (isset($_GET["logout"])) {
    session_destroy();
    header("Location: " . $_SERVER["PHP_SELF"]);
    exit;
}

// Login
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "login") {
    $username = $_POST["username"] ?? "";
    $password = $_POST["password"] ?? "";

    $now      = time();
    $clientIp = alpha_client_ip(false); // set true only behind a trusted proxy
    $ipKey    = alpha_ip_key($clientIp, $ipHashSalt);

    $loginStore = alpha_load_login_security($loginSecurityFile, $attemptWindow, $now);
    $lockRemaining = alpha_login_lock_remaining($loginStore, $ipKey, $now);

    if ($lockRemaining > 0) {
        // IP is currently locked out: do not even check the password.
        $message = "Too many failed login attempts. This address is temporarily blocked. Try again in " . alpha_human_duration($lockRemaining) . ".";
        $messageType = "error";
    } else {
        // Always run password_verify (against a dummy hash on username
        // mismatch) so response time does not reveal whether the username
        // exists -- this prevents username enumeration via timing.
        $dummyHash = '$2y$12$0000000000000000000000000000000000000000000000000000a';
        $userMatch = hash_equals($adminUser, $username);
        $passMatch = password_verify($password, $userMatch ? $adminPassHash : $dummyHash);

        if ($userMatch && $passMatch) {
            // Success: clear any failure record for this IP.
            unset($loginStore[$ipKey]);
            alpha_save_json($loginSecurityFile, $loginStore);

            session_regenerate_id(true);
            $_SESSION["admin_logged_in"] = true;
            $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
            header("Location: " . $_SERVER["PHP_SELF"]);
            exit;
        } else {
            // Failure: record it and possibly trigger a lockout.
            $loginStore = alpha_register_failed_login(
                $loginStore, $ipKey, $now,
                $maxLoginAttempts, $attemptWindow, $lockoutSeconds
            );
            alpha_save_json($loginSecurityFile, $loginStore);

            $newRemaining = alpha_login_lock_remaining($loginStore, $ipKey, $now);
            if ($newRemaining > 0) {
                $message = "Too many failed login attempts. This address is now blocked for " . alpha_human_duration($newRemaining) . ".";
            } else {
                $attemptsLeft = max(0, $maxLoginAttempts - (int)($loginStore[$ipKey]["fails"] ?? 0));
                $message = "Invalid username or password." . ($attemptsLeft > 0 ? " " . $attemptsLeft . " attempt" . ($attemptsLeft === 1 ? "" : "s") . " left before this address is blocked." : "");
            }
            $messageType = "error";
        }
    }
}

// View/download file only after login
if (alpha_is_logged_in() && (isset($_GET["view"]) || isset($_GET["download"]))) {
    $fileName = isset($_GET["view"]) ? $_GET["view"] : $_GET["download"];
    $filePath = alpha_get_file_path($fileName, $uploadDir);

    if ($filePath === false) {
        http_response_code(404);
        echo "File not found or blocked.";
        exit;
    }

    $displayName = basename($filePath);
    $ext = strtolower(pathinfo($displayName, PATHINFO_EXTENSION));
    $mimeType = alpha_detect_mime($filePath);

    $inlineAllowed = in_array($ext, ["jpg", "jpeg", "png", "gif", "webp", "pdf", "txt"], true);
    $disposition = (isset($_GET["view"]) && $inlineAllowed) ? "inline" : "attachment";

    header_remove("Content-Security-Policy");
    header("Content-Security-Policy: sandbox");
    header("X-Content-Type-Options: nosniff");
    header("Cache-Control: private, no-store, max-age=0");
    header("Content-Type: " . $mimeType);
    header("Content-Length: " . filesize($filePath));
    header("Content-Disposition: " . $disposition . "; filename=\"" . addslashes($displayName) . "\"");

    readfile($filePath);
    exit;
}

$metadata = alpha_load_json($metadataFile);

// Import old approval status if old approvals.json exists
$oldApprovals = alpha_load_json($oldApprovalFile);
if (!empty($oldApprovals)) {
    foreach ($oldApprovals as $oldFile => $oldStatus) {
        $oldFile = basename($oldFile);
        if (!isset($metadata[$oldFile]) || !is_array($metadata[$oldFile])) {
            $metadata[$oldFile] = [];
        }

        if (($oldStatus === "approved") && empty($metadata[$oldFile]["status"])) {
            $metadata[$oldFile]["status"] = "approved";
        }
    }
}

// Save approvals
if (alpha_is_logged_in() && $_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "save_approvals") {
    if (!isset($_POST["csrf_token"]) || !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])) {
        $message = "Security token mismatch. Please try again.";
        $messageType = "error";
    } else {
        $visibleFiles = $_POST["visible_files"] ?? [];
        $approvedFiles = $_POST["approved_files"] ?? [];

        if (!is_array($visibleFiles)) {
            $visibleFiles = [];
        }

        if (!is_array($approvedFiles)) {
            $approvedFiles = [];
        }

        $approvedMap = [];

        foreach ($approvedFiles as $approvedFile) {
            $approvedMap[basename($approvedFile)] = true;
        }

        foreach ($visibleFiles as $visibleFile) {
            $fileName = basename($visibleFile);

            if (alpha_get_file_path($fileName, $uploadDir) !== false) {
                if (!isset($metadata[$fileName]) || !is_array($metadata[$fileName])) {
                    $metadata[$fileName] = [];
                }

                $metadata[$fileName]["file_name"] = $fileName;
                $metadata[$fileName]["status"] = isset($approvedMap[$fileName]) ? "approved" : "pending";
            }
        }

        if (alpha_save_json($metadataFile, $metadata)) {
            $message = "Approval changes saved successfully.";
            $messageType = "success";
        } else {
            $message = "Could not save approval data. Please check uploads folder permission.";
            $messageType = "error";
        }
    }
}


// Soft delete file only after login
if (alpha_is_logged_in() && $_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete_file") {
    if (!isset($_POST["csrf_token"]) || !hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"])) {
        $message = "Security token mismatch. Please try again.";
        $messageType = "error";
    } elseif (($_POST["confirm_delete"] ?? "") !== "1") {
        $message = "Delete confirmation missing.";
        $messageType = "error";
    } else {
        $fileName = basename($_POST["file_name"] ?? "");
        $filePath = alpha_get_file_path($fileName, $uploadDir);

        if ($filePath === false) {
            $message = "File not found or already removed from active list.";
            $messageType = "error";
        } else {
            $deletedDir = $uploadDir . "_deleted/";

            if (!is_dir($deletedDir)) {
                mkdir($deletedDir, 0755, true);
            }

            $deletedIndex = $deletedDir . "index.html";
            if (!file_exists($deletedIndex)) {
                file_put_contents($deletedIndex, "");
            }

            $deletedHtaccess = $deletedDir . ".htaccess";
            if (!file_exists($deletedHtaccess)) {
                $deletedRules = "Options -Indexes -ExecCGI\n"
                    . "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
                    . "<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n"
                    . "RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .php8 .phps .phar .pl .py .cgi .sh\n"
                    . "<FilesMatch \"(?i)\\.(php|phtml|php[0-9]|phps|phar|pl|py|cgi|sh|bash|exe)$\">\n    SetHandler none\n    ForceType application/octet-stream\n</FilesMatch>\n"
                    . "<IfModule mod_php.c>\n    php_admin_flag engine off\n</IfModule>\n";
                file_put_contents($deletedHtaccess, $deletedRules);
            }

            $deletedName = date("Ymd_His") . "_" . bin2hex(random_bytes(4)) . "_" . $fileName;
            $deletedPath = $deletedDir . $deletedName;

            if (rename($filePath, $deletedPath)) {
                if (!isset($metadata[$fileName]) || !is_array($metadata[$fileName])) {
                    $metadata[$fileName] = [];
                }

                $metadata[$fileName]["file_name"] = $fileName;
                $metadata[$fileName]["status"] = "deleted";
                $metadata[$fileName]["deleted_at"] = date("Y-m-d H:i:s");
                $metadata[$fileName]["deleted_file_name"] = $deletedName;
                $metadata[$fileName]["delete_type"] = "soft_delete";

                alpha_save_json($metadataFile, $metadata);

                $message = "File soft deleted successfully. It was moved to uploads/_deleted/.";
                $messageType = "success";
            } else {
                $message = "Could not soft delete file. Please check folder permission.";
                $messageType = "error";
            }
        }
    }
}

// Load uploaded files
$allFiles = [];
$totalSize = 0;

if (alpha_is_logged_in() && is_dir($uploadDir)) {
    $items = scandir($uploadDir);

    foreach ($items as $item) {
        if (
            $item === "." ||
            $item === ".." ||
            $item === ".htaccess" ||
            $item === "index.html" ||
            $item === "approvals.json" ||
            $item === "upload_data.json" ||
            $item === "_deleted"
        ) {
            continue;
        }

        $path = $uploadDir . $item;

        if (is_file($path)) {
            $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
            $fileMeta = isset($metadata[$item]) && is_array($metadata[$item]) ? $metadata[$item] : [];
            $size = filesize($path);

            $uploadedAt = $fileMeta["uploaded_at"] ?? date("Y-m-d H:i:s", filemtime($path));
            $timestamp = strtotime($uploadedAt);
            if ($timestamp === false) {
                $timestamp = filemtime($path);
            }

            $status = ($fileMeta["status"] ?? "pending") === "approved" ? "approved" : "pending";
            $email = trim($fileMeta["email"] ?? "");

            $allFiles[] = [
                "name" => $item,
                "short_name" => alpha_short_file_name($item),
                "original_name" => $fileMeta["original_name"] ?? $item,
                "email" => $email !== "" ? $email : "Not provided",
                "ext" => $ext,
                "group" => alpha_file_type_group($ext),
                "size" => $size,
                "timestamp" => $timestamp,
                "uploaded_at" => date("Y-m-d H:i:s", $timestamp),
                "status" => $status
            ];

            $totalSize += $size;
        }
    }

    usort($allFiles, function ($a, $b) {
        return $b["timestamp"] - $a["timestamp"];
    });
}

// Filters
$q = trim($_GET["q"] ?? "");
$type = $_GET["type"] ?? "all";
$status = $_GET["status"] ?? "all";
$dateFrom = trim($_GET["date_from"] ?? "");
$dateTo = trim($_GET["date_to"] ?? "");
$perPage = (int)($_GET["per_page"] ?? 10);
$page = (int)($_GET["page"] ?? 1);

$validTypes = ["all", "image", "pdf", "document", "zip", "text", "other"];
$validStatuses = ["all", "approved", "pending"];
$validPerPage = [5, 10, 20, 50];

if (!in_array($type, $validTypes, true)) {
    $type = "all";
}

if (!in_array($status, $validStatuses, true)) {
    $status = "all";
}

if (!in_array($perPage, $validPerPage, true)) {
    $perPage = 10;
}

if ($page < 1) {
    $page = 1;
}

$dateFromTs = $dateFrom !== "" ? strtotime($dateFrom . " 00:00:00") : false;
$dateToTs = $dateTo !== "" ? strtotime($dateTo . " 23:59:59") : false;

$filteredFiles = [];

foreach ($allFiles as $file) {
    if ($q !== "") {
        $needle = strtolower($q);
        $haystack = strtolower($file["name"] . " " . $file["original_name"] . " " . $file["email"]);

        if (strpos($haystack, $needle) === false) {
            continue;
        }
    }

    if ($type !== "all" && $file["group"] !== $type) {
        continue;
    }

    if ($status !== "all" && $file["status"] !== $status) {
        continue;
    }

    if ($dateFromTs !== false && $file["timestamp"] < $dateFromTs) {
        continue;
    }

    if ($dateToTs !== false && $file["timestamp"] > $dateToTs) {
        continue;
    }

    $filteredFiles[] = $file;
}

$totalFiles = count($allFiles);
$approvedCount = 0;
$pendingCount = 0;
$deletedCount = 0;

foreach ($metadata as $metaItem) {
    if (is_array($metaItem) && (($metaItem["status"] ?? "") === "deleted")) {
        $deletedCount++;
    }
}

foreach ($allFiles as $file) {
    if ($file["status"] === "approved") {
        $approvedCount++;
    } else {
        $pendingCount++;
    }
}

$filteredTotal = count($filteredFiles);
$totalPages = max(1, (int)ceil($filteredTotal / $perPage));

if ($page > $totalPages) {
    $page = $totalPages;
}

$offset = ($page - 1) * $perPage;
$pagedFiles = array_slice($filteredFiles, $offset, $perPage);

$showFrom = $filteredTotal > 0 ? $offset + 1 : 0;
$showTo = min($offset + $perPage, $filteredTotal);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AT Space | Secure Admin Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Inter", "Segoe UI", Arial, sans-serif; }
        body { min-height: 100vh; background: #eef3fb; color: #101828; }
        a { text-decoration: none; }

        .login-page {
            min-height: 100vh;
            background:
                radial-gradient(circle at top left, rgba(13, 110, 253, 0.35), transparent 36%),
                linear-gradient(135deg, #06142e, #0a2d67 55%, #0d6efd);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .login-card {
            width: 100%;
            max-width: 430px;
            background: rgba(255,255,255,0.97);
            border-radius: 26px;
            padding: 36px;
            box-shadow: 0 34px 90px rgba(0,0,0,0.28);
        }

        /* Sidebar removed: dashboard now uses a single full-width column. */
        .app { min-height: 100vh; }

        .brand { display: flex; align-items: center; gap: 13px; }
        .brand-logo {
            width: 52px;
            height: 52px;
            border-radius: 17px;
            background: linear-gradient(135deg, #0d6efd, #5aa4ff);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
            font-size: 20px;
            box-shadow: 0 16px 32px rgba(13,110,253,0.28);
            color: #fff;
            flex: 0 0 auto;
        }

        .brand h1 { font-size: 21px; margin-bottom: 3px; color: inherit; }
        .brand p { font-size: 12px; color: #b8c7dc; }

        /* Logout relocated to the top-right navigation bar. */
        .logout {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 11px 16px;
            border-radius: 13px;
            background: #fff1f1;
            color: #b42318;
            border: 1px solid #ffd0d0;
            font-weight: 900;
            font-size: 14px;
            white-space: nowrap;
        }

        .logout:hover { background: #ffe4e4; }
        .logout svg { width: 18px; height: 18px; }

        .main { padding: 28px; max-width: 1320px; margin: 0 auto; width: 100%; }

        /* Top navigation bar: brand on the left, actions (storage + logout) on the right. */
        .topbar {
            background: #ffffff;
            border-radius: 24px;
            padding: 18px 24px;
            display: flex;
            justify-content: space-between;
            gap: 18px;
            align-items: center;
            flex-wrap: wrap;
            box-shadow: 0 14px 40px rgba(16, 24, 40, 0.08);
            margin-bottom: 22px;
        }

        .topbar .brand h1 { color: #0b1f3a; }
        .topbar .brand p { color: #667085; }

        .topbar-actions {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .page-head { margin-bottom: 22px; padding: 0 4px; }
        .page-head h2 { font-size: 27px; letter-spacing: -0.03em; color: #0b1f3a; margin-bottom: 6px; }
        .page-head p { color: #667085; font-size: 14px; max-width: 760px; }

        .topbar-badge {
            background: #eff6ff;
            color: #0d47a1;
            padding: 10px 13px;
            border-radius: 999px;
            font-weight: 900;
            font-size: 13px;
            white-space: nowrap;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 18px;
            margin-bottom: 22px;
        }

        .stat-card, .card {
            background: #ffffff;
            border-radius: 22px;
            box-shadow: 0 14px 40px rgba(16, 24, 40, 0.08);
            border: 1px solid #edf1f7;
        }

        .stat-card { padding: 22px; }
        .stat-card span { display: block; color: #667085; font-size: 13px; font-weight: 800; margin-bottom: 8px; }
        .stat-card strong { color: #0b1f3a; font-size: 29px; letter-spacing: -0.03em; }

        .card { margin-bottom: 22px; border-radius: 24px; }
        .card-head {
            padding: 22px 24px;
            border-bottom: 1px solid #edf1f7;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
        }

        .card-head h3 { color: #0b1f3a; font-size: 19px; margin-bottom: 5px; }
        .card-head p { color: #667085; font-size: 13px; }

        .filter-body { padding: 22px 24px 24px; }

        .filter-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr 1fr 1fr 1fr 0.8fr;
            gap: 13px;
            align-items: end;
        }

        .form-group label {
            display: block;
            font-size: 12px;
            color: #344054;
            font-weight: 900;
            margin-bottom: 8px;
        }

        input[type="text"], input[type="password"], input[type="date"], select {
            width: 100%;
            border: 1px solid #d0d5dd;
            background: #ffffff;
            border-radius: 13px;
            padding: 13px 14px;
            font-size: 14px;
            color: #101828;
            outline: none;
        }

        input:focus, select:focus {
            border-color: #0d6efd;
            box-shadow: 0 0 0 4px rgba(13,110,253,0.12);
        }

        .btn {
            border: none;
            border-radius: 13px;
            padding: 13px 16px;
            font-weight: 900;
            font-size: 14px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            white-space: nowrap;
        }

        .btn-primary { background: linear-gradient(135deg, #0d6efd, #084298); color: #ffffff; }
        .btn-muted { background: #f2f4f7; color: #344054; }
        .login-card .btn-primary { width: 100%; margin-top: 4px; }

        .message {
            padding: 14px 16px;
            border-radius: 14px;
            margin-bottom: 18px;
            font-size: 14px;
            font-weight: 800;
        }

        .success { background: #e7f8ee; color: #147a3d; border: 1px solid #bce8cd; }
        .error { background: #fdeaea; color: #b42318; border: 1px solid #f5c2c0; }

        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 1080px; }

        th {
            background: #f8fafc;
            color: #667085;
            font-size: 12px;
            text-align: left;
            padding: 14px 18px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            border-bottom: 1px solid #edf1f7;
        }

        td {
            padding: 16px 18px;
            border-bottom: 1px solid #edf1f7;
            color: #344054;
            font-size: 14px;
            vertical-align: middle;
        }

        tr:hover td { background: #fbfdff; }

        .file-cell { display: flex; align-items: center; gap: 12px; max-width: 320px; }

        .file-type-icon {
            width: 44px;
            height: 44px;
            border-radius: 15px;
            background: #eff6ff;
            color: #0d47a1;
            font-weight: 900;
            font-size: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex: 0 0 auto;
        }

        .file-title { font-weight: 900; color: #101828; white-space: nowrap; }
        .file-original {
            color: #98a2b3;
            font-size: 12px;
            margin-top: 4px;
            max-width: 250px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .email-cell {
            color: #0b1f3a;
            font-weight: 700;
            max-width: 220px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .pill {
            display: inline-flex;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
        }

        .pill-approved { background: #ecfdf3; color: #027a48; }
        .pill-pending { background: #fff7e6; color: #b54708; }

        .approval-check {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-weight: 900;
            color: #344054;
            cursor: pointer;
        }

        .approval-check input { width: 18px; height: 18px; accent-color: #0d6efd; }

        .icon-actions { display: flex; gap: 8px; }

        .icon-btn {
            width: 38px;
            height: 38px;
            border-radius: 12px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: #0d47a1;
            background: #eff6ff;
            border: 1px solid #d7e7ff;
        }

        .icon-btn.download { color: #027a48; background: #ecfdf3; border-color: #c8f1d8; }
        .icon-btn.delete { color: #b42318; background: #fff1f1; border-color: #ffd0d0; }
        .icon-btn svg { width: 18px; height: 18px; }

        .delete-modal {
            position: fixed;
            inset: 0;
            z-index: 9999;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: rgba(7, 29, 58, 0.68);
            backdrop-filter: blur(6px);
        }

        .delete-modal:target {
            display: flex;
        }

        .modal-card {
            width: 100%;
            max-width: 460px;
            background: #ffffff;
            border-radius: 24px;
            box-shadow: 0 34px 90px rgba(0,0,0,0.30);
            overflow: hidden;
        }

        .modal-head {
            padding: 24px 24px 16px;
            border-bottom: 1px solid #edf1f7;
        }

        .modal-icon {
            width: 54px;
            height: 54px;
            border-radius: 18px;
            background: #fff1f1;
            color: #b42318;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
        }

        .modal-icon svg {
            width: 25px;
            height: 25px;
        }

        .modal-head h3 {
            color: #101828;
            font-size: 22px;
            margin-bottom: 8px;
        }

        .modal-head p {
            color: #667085;
            font-size: 14px;
            line-height: 1.6;
        }

        .modal-file {
            margin-top: 14px;
            padding: 12px;
            background: #f8fafc;
            border-radius: 14px;
            color: #344054;
            font-size: 13px;
            font-weight: 800;
            word-break: break-all;
        }

        .modal-actions {
            padding: 18px 24px 24px;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            flex-wrap: wrap;
        }

        .btn-danger {
            background: #d92d20;
            color: #ffffff;
        }

        .btn-cancel {
            background: #f2f4f7;
            color: #344054;
        }

        .table-bottom {
            padding: 18px 24px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;
        }

        .save-panel {
            padding: 18px 24px;
            display: flex;
            justify-content: flex-end;
            border-top: 1px solid #edf1f7;
        }

        .result-text { color: #667085; font-weight: 800; font-size: 13px; }
        .pagination { display: flex; gap: 8px; flex-wrap: wrap; }

        .page-link {
            min-width: 38px;
            height: 38px;
            padding: 0 12px;
            border-radius: 12px;
            background: #f2f4f7;
            color: #344054;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
            font-size: 13px;
        }

        .page-link.active { background: #0d6efd; color: #ffffff; }
        .page-link.disabled { opacity: 0.45; pointer-events: none; }

        .empty { padding: 58px 24px; text-align: center; color: #667085; }
        .empty strong { display: block; color: #0b1f3a; margin-bottom: 6px; font-size: 18px; }

        .footer { color: #667085; font-size: 13px; text-align: center; padding: 10px 0 24px; }

        /* Mobile responsive dashboard */
        @media (max-width: 1180px) {
            .stats {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .filter-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        @media (max-width: 720px) {
            body {
                background: #eef3fb;
                overflow-x: hidden;
            }

            .main {
                padding: 12px;
            }

            .stats, .filter-grid {
                grid-template-columns: 1fr;
            }

            /* Nav bar stacks but logout stays reachable at the top. */
            .topbar {
                padding: 14px 16px;
                gap: 12px;
                align-items: flex-start;
                flex-direction: column;
            }

            .topbar-actions {
                width: 100%;
                justify-content: space-between;
            }

            .save-panel .btn, .filter-grid .btn { width: 100%; }
            .save-panel { justify-content: stretch; }

            .brand-logo {
                width: 44px;
                height: 44px;
                border-radius: 14px;
                font-size: 16px;
            }

            .brand h1 {
                font-size: 18px;
            }

            .brand p {
                font-size: 11px;
            }

            .topbar {
                padding: 14px 16px;
                border-radius: 18px;
                margin-bottom: 12px;
            }

            .page-head h2 {
                font-size: 22px;
                line-height: 1.2;
            }

            .page-head p {
                font-size: 12px;
                line-height: 1.5;
            }

            .topbar-badge {
                font-size: 12px;
                padding: 8px 10px;
            }

            .stats {
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 10px;
                margin-bottom: 12px;
            }

            .stat-card {
                padding: 14px;
                border-radius: 16px;
            }

            .stat-card span {
                font-size: 11px;
                margin-bottom: 6px;
            }

            .stat-card strong {
                font-size: 22px;
            }

            .card {
                border-radius: 18px;
                margin-bottom: 12px;
            }

            .card-head {
                padding: 16px;
            }

            .card-head h3 {
                font-size: 17px;
            }

            .card-head p {
                font-size: 12px;
                line-height: 1.5;
            }

            .filter-body {
                padding: 14px 16px 16px;
            }

            .filter-grid {
                grid-template-columns: 1fr;
                gap: 10px;
            }

            .form-group label {
                font-size: 11px;
                margin-bottom: 6px;
            }

            input[type="text"],
            input[type="password"],
            input[type="date"],
            select {
                min-height: 44px;
                padding: 11px 12px;
                border-radius: 12px;
                font-size: 13px;
            }

            .btn {
                min-height: 44px;
                padding: 11px 14px;
                border-radius: 12px;
                width: 100%;
            }

            .table-wrap {
                overflow: visible;
                padding: 0 12px 12px;
            }

            table {
                min-width: 0;
                width: 100%;
                border-collapse: separate;
                border-spacing: 0 12px;
            }

            thead {
                display: none;
            }

            tbody,
            tr,
            td {
                display: block;
                width: 100%;
            }

            tr {
                background: #ffffff;
                border: 1px solid #edf1f7;
                border-radius: 18px;
                box-shadow: 0 10px 25px rgba(16, 24, 40, 0.07);
                padding: 12px;
                margin-bottom: 12px;
            }

            td {
                border-bottom: none;
                padding: 10px 0;
                display: flex;
                align-items: flex-start;
                justify-content: space-between;
                gap: 14px;
                font-size: 13px;
            }

            td::before {
                content: attr(data-label);
                flex: 0 0 92px;
                max-width: 92px;
                color: #667085;
                font-size: 11px;
                font-weight: 900;
                text-transform: uppercase;
                letter-spacing: 0.03em;
                padding-top: 2px;
            }

            td[data-label="File"] {
                display: block;
                padding-top: 4px;
            }

            td[data-label="File"]::before {
                display: block;
                max-width: none;
                margin-bottom: 8px;
            }

            .file-cell {
                max-width: 100%;
                align-items: flex-start;
            }

            .file-type-icon {
                width: 40px;
                height: 40px;
                border-radius: 13px;
                font-size: 10px;
            }

            .file-title {
                white-space: normal;
                line-height: 1.35;
                word-break: break-word;
                font-size: 13px;
            }

            .file-original {
                max-width: 100%;
                white-space: normal;
                word-break: break-word;
                font-size: 11px;
            }

            .email-cell {
                max-width: 100%;
                white-space: normal;
                word-break: break-word;
                text-align: right;
                font-size: 12px;
            }

            .pill {
                font-size: 11px;
                padding: 5px 8px;
            }

            .approval-check {
                font-size: 12px;
            }

            .icon-actions {
                justify-content: flex-end;
            }

            .icon-btn {
                width: 36px;
                height: 36px;
                border-radius: 11px;
            }

            .save-panel {
                padding: 12px;
                justify-content: stretch;
            }

            .table-bottom {
                padding: 12px 16px 18px;
                flex-direction: column;
                align-items: flex-start;
            }

            .pagination {
                width: 100%;
                gap: 6px;
            }

            .page-link {
                min-width: 34px;
                height: 34px;
                border-radius: 10px;
                font-size: 12px;
                padding: 0 9px;
            }

            .delete-modal {
                padding: 14px;
            }

            .modal-card {
                border-radius: 20px;
            }

            .modal-head {
                padding: 20px 20px 14px;
            }

            .modal-head h3 {
                font-size: 20px;
            }

            .modal-head p {
                font-size: 13px;
            }

            .modal-actions {
                padding: 16px 20px 20px;
                flex-direction: column;
            }

            .modal-actions .btn,
            .modal-actions form {
                width: 100%;
            }

            .footer {
                font-size: 11px;
                padding-bottom: 16px;
            }
        }

        @media (max-width: 380px) {
            .stats {
                grid-template-columns: 1fr;
            }

            td {
                display: block;
            }

            td::before {
                display: block;
                max-width: none;
                margin-bottom: 6px;
            }

            .email-cell {
                text-align: left;
            }

            .icon-actions {
                justify-content: flex-start;
            }
        }

    </style>
</head>
<body>

<?php if (!alpha_is_logged_in()): ?>

<div class="login-page">
    <div class="login-card">
        <div class="brand" style="color:#101828;margin-bottom:28px;">
            <div class="brand-logo">AN</div>
            <div>
                <h1>AT Space</h1>
                <p style="color:#667085;">Secure Admin Dashboard</p>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="message <?php echo alpha_clean($messageType); ?>">
                <?php echo alpha_clean($message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" autocomplete="off">
            <input type="hidden" name="action" value="login">

            <div class="form-group" style="margin-bottom:15px;">
                <label>Username</label>
                <input type="text" name="username" placeholder="admin" required>
            </div>

            <div class="form-group" style="margin-bottom:16px;">
                <label>Password</label>
                <input type="password" name="password" placeholder="Password" required>
            </div>

            <button class="btn btn-primary" type="submit">Login to Dashboard</button>
        </form>
    </div>
</div>

<?php else: ?>

<div class="app">
    <main class="main">
        <nav class="topbar">
            <div class="brand">
                <div class="brand-logo">AN</div>
                <div>
                    <h1>AT Space</h1>
                    <p>Secure Admin Console</p>
                </div>
            </div>

            <div class="topbar-actions">
                <div class="topbar-badge">Storage: <?php echo alpha_format_size($totalSize); ?></div>
                <a class="logout" href="?logout=1">
                    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                        <path d="M15 4H6C4.9 4 4 4.9 4 6V18C4 19.1 4.9 20 6 20H15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M16 8L20 12L16 16" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M20 12H9" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                    Logout
                </a>
            </div>
        </nav>

        <div class="page-head">
            <h2>File Review Dashboard</h2>
            <p>Securely manage public uploaded files with email, date filter, approval status and protected download.</p>
        </div>

        <?php if ($message): ?>
            <div class="message <?php echo alpha_clean($messageType); ?>">
                <?php echo alpha_clean($message); ?>
            </div>
        <?php endif; ?>

        <section class="stats">
            <div class="stat-card">
                <span>Total Files</span>
                <strong><?php echo $totalFiles; ?></strong>
            </div>

            <div class="stat-card">
                <span>Total Size</span>
                <strong><?php echo alpha_format_size($totalSize); ?></strong>
            </div>

            <div class="stat-card">
                <span>Approved</span>
                <strong><?php echo $approvedCount; ?></strong>
            </div>

            <div class="stat-card">
                <span>Pending</span>
                <strong><?php echo $pendingCount; ?></strong>
            </div>

            <div class="stat-card">
                <span>Deleted</span>
                <strong><?php echo $deletedCount; ?></strong>
            </div>
        </section>

        <section class="card">
            <div class="card-head">
                <div>
                    <h3>Search & Filters</h3>
                    <p>Search by file name/email, filter by type, approval status and upload date.</p>
                </div>
            </div>

            <div class="filter-body">
                <form method="GET">
                    <div class="filter-grid">
                        <div class="form-group">
                            <label>Search File / Email</label>
                            <input type="text" name="q" value="<?php echo alpha_clean($q); ?>" placeholder="Search file name or email">
                        </div>

                        <div class="form-group">
                            <label>File Type</label>
                            <select name="type">
                                <option value="all" <?php echo $type === "all" ? "selected" : ""; ?>>All Types</option>
                                <option value="image" <?php echo $type === "image" ? "selected" : ""; ?>>Images</option>
                                <option value="pdf" <?php echo $type === "pdf" ? "selected" : ""; ?>>PDF</option>
                                <option value="document" <?php echo $type === "document" ? "selected" : ""; ?>>Documents</option>
                                <option value="zip" <?php echo $type === "zip" ? "selected" : ""; ?>>ZIP</option>
                                <option value="text" <?php echo $type === "text" ? "selected" : ""; ?>>Text</option>
                                <option value="other" <?php echo $type === "other" ? "selected" : ""; ?>>Other</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label>Approval</label>
                            <select name="status">
                                <option value="all" <?php echo $status === "all" ? "selected" : ""; ?>>All Status</option>
                                <option value="approved" <?php echo $status === "approved" ? "selected" : ""; ?>>Approved</option>
                                <option value="pending" <?php echo $status === "pending" ? "selected" : ""; ?>>Pending</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label>From Date</label>
                            <input type="date" name="date_from" value="<?php echo alpha_clean($dateFrom); ?>">
                        </div>

                        <div class="form-group">
                            <label>To Date</label>
                            <input type="date" name="date_to" value="<?php echo alpha_clean($dateTo); ?>">
                        </div>

                        <div class="form-group">
                            <label>Per Page</label>
                            <select name="per_page">
                                <option value="5" <?php echo $perPage === 5 ? "selected" : ""; ?>>5</option>
                                <option value="10" <?php echo $perPage === 10 ? "selected" : ""; ?>>10</option>
                                <option value="20" <?php echo $perPage === 20 ? "selected" : ""; ?>>20</option>
                                <option value="50" <?php echo $perPage === 50 ? "selected" : ""; ?>>50</option>
                            </select>
                        </div>

                        <button class="btn btn-primary" type="submit">Apply</button>
                        <a class="btn btn-muted" href="<?php echo alpha_clean($_SERVER["PHP_SELF"]); ?>">Reset</a>
                    </div>
                </form>
            </div>
        </section>

        <section class="card">
            <div class="card-head">
                <div>
                    <h3>Uploaded Files</h3>
                    <p>Showing <?php echo $showFrom; ?>-<?php echo $showTo; ?> of <?php echo $filteredTotal; ?> matching files.</p>
                </div>
            </div>

            <?php if ($filteredTotal > 0): ?>
                <form id="approvalForm" method="POST">
                    <input type="hidden" name="action" value="save_approvals">
                    <input type="hidden" name="csrf_token" value="<?php echo alpha_clean($_SESSION["csrf_token"]); ?>">
                </form>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Email</th>
                                <th>Size</th>
                                <th>Uploaded Date</th>
                                <th>Status</th>
                                <th>Approve</th>
                                <th>Action</th>
                            </tr>
                        </thead>

                        <tbody>
                            <?php foreach ($pagedFiles as $file): ?>
                                <tr>
                                    <td data-label="File">
                                        <div class="file-cell">
                                            <div class="file-type-icon"><?php echo alpha_clean(alpha_file_badge($file["ext"])); ?></div>
                                            <div>
                                                <div class="file-title" title="<?php echo alpha_clean($file["name"]); ?>">
                                                    <?php echo alpha_clean($file["short_name"]); ?>
                                                </div>
                                                <div class="file-original" title="<?php echo alpha_clean($file["original_name"]); ?>">
                                                    <?php echo alpha_clean($file["original_name"]); ?>
                                                </div>
                                            </div>
                                        </div>

                                        <input form="approvalForm" type="hidden" name="visible_files[]" value="<?php echo alpha_clean($file["name"]); ?>">
                                    </td>

                                    <td data-label="Email">
                                        <div class="email-cell" title="<?php echo alpha_clean($file["email"]); ?>">
                                            <?php echo alpha_clean($file["email"]); ?>
                                        </div>
                                    </td>

                                    <td data-label="Size"><?php echo alpha_format_size($file["size"]); ?></td>

                                    <td data-label="Uploaded"><?php echo date("Y-m-d h:i A", $file["timestamp"]); ?></td>

                                    <td data-label="Status">
                                        <span class="pill <?php echo $file["status"] === "approved" ? "pill-approved" : "pill-pending"; ?>">
                                            <?php echo alpha_clean($file["status"]); ?>
                                        </span>
                                    </td>

                                    <td data-label="Approve">
                                        <label class="approval-check">
                                            <input
                                                form="approvalForm"
                                                type="checkbox"
                                                name="approved_files[]"
                                                value="<?php echo alpha_clean($file["name"]); ?>"
                                                <?php echo $file["status"] === "approved" ? "checked" : ""; ?>
                                            >
                                            Approve
                                        </label>
                                    </td>

                                    <td data-label="Action">
                                        <div class="icon-actions">
                                            <a class="icon-btn" target="_blank" title="View" href="?view=<?php echo urlencode($file["name"]); ?>">
                                                <svg viewBox="0 0 24 24" fill="none">
                                                    <path d="M2.5 12S5.8 5.5 12 5.5S21.5 12 21.5 12 18.2 18.5 12 18.5 2.5 12 2.5 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                                    <path d="M12 15A3 3 0 1 0 12 9A3 3 0 0 0 12 15Z" stroke="currentColor" stroke-width="2"/>
                                                </svg>
                                            </a>

                                            <a class="icon-btn download" title="Download" href="?download=<?php echo urlencode($file["name"]); ?>">
                                                <svg viewBox="0 0 24 24" fill="none">
                                                    <path d="M12 3V15M12 15L7 10M12 15L17 10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                                    <path d="M5 19H19" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                                </svg>
                                            </a>

                                            <a class="icon-btn delete" title="Delete" href="#delete-<?php echo md5($file["name"]); ?>">
                                                <svg viewBox="0 0 24 24" fill="none">
                                                    <path d="M4 7H20" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                                    <path d="M10 11V17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                                    <path d="M14 11V17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                                    <path d="M6 7L7 20H17L18 7" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                                                    <path d="M9 7V4H15V7" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                                                </svg>
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <?php foreach ($pagedFiles as $file): ?>
                    <div class="delete-modal" id="delete-<?php echo md5($file["name"]); ?>">
                        <div class="modal-card">
                            <div class="modal-head">
                                <div class="modal-icon">
                                    <svg viewBox="0 0 24 24" fill="none">
                                        <path d="M4 7H20" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                        <path d="M10 11V17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                        <path d="M14 11V17" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                                        <path d="M6 7L7 20H17L18 7" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                                        <path d="M9 7V4H15V7" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                                    </svg>
                                </div>

                                <h3>Soft delete this file?</h3>
                                <p>This will remove the file from the active dashboard list only. It will not be permanently deleted. The file will be moved to <strong>uploads/_deleted/</strong>.</p>

                                <div class="modal-file">
                                    <?php echo alpha_clean($file["short_name"]); ?>
                                </div>
                            </div>

                            <div class="modal-actions">
                                <a class="btn btn-cancel" href="#">Cancel</a>

                                <form method="POST">
                                    <input type="hidden" name="action" value="delete_file">
                                    <input type="hidden" name="confirm_delete" value="1">
                                    <input type="hidden" name="csrf_token" value="<?php echo alpha_clean($_SESSION["csrf_token"]); ?>">
                                    <input type="hidden" name="file_name" value="<?php echo alpha_clean($file["name"]); ?>">
                                    <button class="btn btn-danger" type="submit">Yes, Soft Delete</button>
                                </form>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>

                <div class="save-panel">
                    <button class="btn btn-primary" form="approvalForm" type="submit">Save Approval Changes</button>
                </div>

                <div class="table-bottom">
                    <div class="result-text">
                        Page <?php echo $page; ?> of <?php echo $totalPages; ?>
                    </div>

                    <div class="pagination">
                        <a class="page-link <?php echo $page <= 1 ? "disabled" : ""; ?>" href="<?php echo alpha_page_link(1); ?>">First</a>
                        <a class="page-link <?php echo $page <= 1 ? "disabled" : ""; ?>" href="<?php echo alpha_page_link($page - 1); ?>">Prev</a>

                        <?php
                        $startPage = max(1, $page - 2);
                        $endPage = min($totalPages, $page + 2);

                        for ($i = $startPage; $i <= $endPage; $i++):
                        ?>
                            <a class="page-link <?php echo $i === $page ? "active" : ""; ?>" href="<?php echo alpha_page_link($i); ?>">
                                <?php echo $i; ?>
                            </a>
                        <?php endfor; ?>

                        <a class="page-link <?php echo $page >= $totalPages ? "disabled" : ""; ?>" href="<?php echo alpha_page_link($page + 1); ?>">Next</a>
                        <a class="page-link <?php echo $page >= $totalPages ? "disabled" : ""; ?>" href="<?php echo alpha_page_link($totalPages); ?>">Last</a>
                    </div>
                </div>
            <?php else: ?>
                <div class="empty">
                    <strong>No files found</strong>
                    No uploaded files matched your current search or filter.
                </div>
            <?php endif; ?>
        </section>

        <div class="footer">
            © <?php echo date("Y"); ?> AT Space. All rights reserved.
        </div>
    </main>
</div>

<?php endif; ?>

</body>
</html>
