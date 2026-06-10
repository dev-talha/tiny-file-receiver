<?php
/*
    PHP 8.3 Compatible

    AT Space Secure Public Upload Page
    Public users upload files without login.

    Security:
    - Email required
    - CSRF token
    - File extension whitelist
    - MIME type verification
    - Flexible PDF/ZIP extension detection
    - Random server filename
    - No PHP/HTML/JS/SVG executable upload
    - Double-extension script blocking
    - uploads/.htaccess auto-protection
    - Metadata saved to uploads/upload_data.json
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
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'");

$message = "";
$messageType = "";

$uploadDir = __DIR__ . "/uploads/";
$metadataFile = $uploadDir . "upload_data.json";
$maxSize = 20 * 1024 * 1024; // 20MB

$allowedExtensions = ["jpg", "jpeg", "png", "gif", "webp", "pdf", "doc", "docx", "zip", "txt"];

$allowedMimeTypes = [
    "jpg"  => ["image/jpeg", "image/pjpeg"],
    "jpeg" => ["image/jpeg", "image/pjpeg"],
    "png"  => ["image/png", "image/x-png"],
    "gif"  => ["image/gif"],
    "webp" => ["image/webp"],
    "pdf"  => ["application/pdf", "application/x-pdf", "application/acrobat", "applications/vnd.pdf", "text/pdf", "text/x-pdf"],
    "doc"  => ["application/msword", "application/octet-stream"],
    "docx" => [
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
        "application/x-zip",
        "application/x-zip-compressed",
        "application/octet-stream"
    ],
    "zip"  => [
        "application/zip",
        "application/x-zip",
        "application/x-zip-compressed",
        "multipart/x-zip",
        "application/octet-stream"
    ],
    "txt"  => ["text/plain", "application/octet-stream"]
];

$dangerousExtensions = [
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar",
    "html", "htm", "shtml", "js", "mjs", "svg",
    "cgi", "pl", "py", "sh", "bash", "exe", "bat", "cmd", "com"
];

function alpha_clean($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, "UTF-8");
}

function alpha_safe_original_name($name) {
    $name = basename($name);
    $name = preg_replace("/[\x00-\x1F\x7F]/", "", $name);
    $name = preg_replace("/[^a-zA-Z0-9._ -]/", "_", $name);
    $name = preg_replace("/_+/", "_", $name);
    $name = trim($name, " ._");

    if ($name === "") {
        $name = "uploaded_file";
    }

    return $name;
}

function alpha_load_json($path) {
    if (!file_exists($path)) {
        return [];
    }

    $json = file_get_contents($path);
    $data = json_decode($json, true);

    return is_array($data) ? $data : [];
}

function alpha_save_json($path, $data) {
    $json = json_encode($data, JSON_PRETTY_PRINT);

    if ($json === false) {
        return false;
    }

    return file_put_contents($path, $json, LOCK_EX) !== false;
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

function alpha_detect_mime($tmpPath) {
    if (function_exists("finfo_open")) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo) {
            $mime = finfo_file($finfo, $tmpPath);
            finfo_close($finfo);
            return $mime ?: "application/octet-stream";
        }
    }

    if (function_exists("mime_content_type")) {
        return mime_content_type($tmpPath);
    }

    return "application/octet-stream";
}

function alpha_is_zip_signature($tmpPath) {
    $handle = fopen($tmpPath, "rb");
    if (!$handle) {
        return false;
    }

    $signature = fread($handle, 4);
    fclose($handle);

    return $signature === "PK\x03\x04" || $signature === "PK\x05\x06" || $signature === "PK\x07\x08";
}

function alpha_is_pdf_signature($tmpPath) {
    $handle = fopen($tmpPath, "rb");
    if (!$handle) {
        return false;
    }

    $signature = fread($handle, 5);
    fclose($handle);

    return $signature === "%PDF-";
}

function alpha_has_dangerous_extension($fileName, $dangerousExtensions) {
    $lowerName = strtolower($fileName);
    $parts = explode(".", $lowerName);

    if (count($parts) <= 1) {
        return false;
    }

    array_pop($parts); // final extension can be allowed
    foreach ($parts as $part) {
        $part = trim($part);
        if (in_array($part, $dangerousExtensions, true)) {
            return true;
        }
    }

    return false;
}

function alpha_infer_extension_from_content($tmpPath, $mime) {
    $mime = strtolower((string)$mime);

    if ($mime === "application/pdf" || alpha_is_pdf_signature($tmpPath)) {
        return "pdf";
    }

    if (
        in_array($mime, ["application/zip", "application/x-zip", "application/x-zip-compressed", "multipart/x-zip", "application/octet-stream"], true)
        && alpha_is_zip_signature($tmpPath)
    ) {
        return "zip";
    }

    if ($mime === "image/jpeg") {
        return "jpg";
    }

    if ($mime === "image/png") {
        return "png";
    }

    if ($mime === "image/gif") {
        return "gif";
    }

    if ($mime === "image/webp") {
        return "webp";
    }

    if ($mime === "text/plain") {
        return "txt";
    }

    return "";
}

function alpha_mime_allowed($extension, $mime, $tmpPath, $allowedMimeTypes) {
    $extension = strtolower($extension);
    $mime = strtolower((string)$mime);

    if (!isset($allowedMimeTypes[$extension])) {
        return false;
    }

    if (in_array($mime, $allowedMimeTypes[$extension], true)) {
        return true;
    }

    if ($extension === "pdf" && alpha_is_pdf_signature($tmpPath)) {
        return true;
    }

    if (in_array($extension, ["docx", "zip"], true) && alpha_is_zip_signature($tmpPath)) {
        return true;
    }

    return false;
}

alpha_prepare_upload_folder($uploadDir);

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

// Simple session based rate limit
if (!isset($_SESSION["upload_attempts"])) {
    $_SESSION["upload_attempts"] = [];
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_FILES["file"])) {
    $now = time();
    $_SESSION["upload_attempts"] = array_values(array_filter($_SESSION["upload_attempts"], function ($time) use ($now) {
        return ($now - $time) < 600;
    }));

    $_SESSION["upload_attempts"][] = $now;

    $email = trim($_POST["email"] ?? "");
    $csrfToken = $_POST["csrf_token"] ?? "";
    $honeypot = trim($_POST["website"] ?? "");
    $file = $_FILES["file"];

    if (count($_SESSION["upload_attempts"]) > 12) {
        $message = "Too many upload attempts. Please try again later.";
        $messageType = "error";
    } elseif ($honeypot !== "") {
        $message = "Upload blocked.";
        $messageType = "error";
    } elseif (!hash_equals($_SESSION["csrf_token"], $csrfToken)) {
        $message = "Security token mismatch. Please refresh the page and try again.";
        $messageType = "error";
    } elseif ($email === "" || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Please enter a valid email address.";
        $messageType = "error";
    } elseif (!isset($file["error"]) || is_array($file["error"])) {
        $message = "Invalid upload request.";
        $messageType = "error";
    } elseif ($file["error"] === UPLOAD_ERR_OK) {
        if (!is_uploaded_file($file["tmp_name"])) {
            $message = "Invalid uploaded file.";
            $messageType = "error";
        } else {
            $rawOriginalName = basename((string)$file["name"]);
            $originalName = alpha_safe_original_name($rawOriginalName);
            $detectedMime = alpha_detect_mime($file["tmp_name"]);

            // Get extension from original filename first
            $extension = strtolower(pathinfo($rawOriginalName, PATHINFO_EXTENSION));
            $extension = preg_replace("/[^a-z0-9]/", "", $extension);

            // If original filename extension is missing/invalid, infer from real content
            if ($extension === "" || !in_array($extension, $allowedExtensions, true)) {
                $extension = alpha_infer_extension_from_content($file["tmp_name"], $detectedMime);
            }

            if (alpha_has_dangerous_extension($rawOriginalName, $dangerousExtensions)) {
                $message = "This file name contains a blocked script extension.";
                $messageType = "error";
            } elseif ($extension === "" || !in_array($extension, $allowedExtensions, true)) {
                $message = "Invalid file type. Please upload a valid JPG, PNG, GIF, WEBP, PDF, DOC, DOCX, ZIP, or TXT file.";
                $messageType = "error";
            } elseif (in_array($extension, $dangerousExtensions, true)) {
                $message = "This file type is not allowed for security reasons.";
                $messageType = "error";
            } elseif ((int)$file["size"] <= 0 || (int)$file["size"] > $maxSize) {
                $message = "File size is too large. Maximum allowed size is 20MB.";
                $messageType = "error";
            } elseif (!alpha_mime_allowed($extension, $detectedMime, $file["tmp_name"], $allowedMimeTypes)) {
                $message = "File content does not match the allowed file type.";
                $messageType = "error";
            } else {
                $randomName = bin2hex(random_bytes(16));
                $newFileName = "alphanet_" . date("Ymd_His") . "_" . $randomName . "." . $extension;
                $targetPath = $uploadDir . $newFileName;

                if (move_uploaded_file($file["tmp_name"], $targetPath)) {
                    chmod($targetPath, 0644);

                    $metadata = alpha_load_json($metadataFile);
                    $metadata[$newFileName] = [
                        "file_name" => $newFileName,
                        "original_name" => $originalName,
                        "email" => $email,
                        "size" => (int)$file["size"],
                        "extension" => $extension,
                        "mime_type" => $detectedMime,
                        "uploaded_at" => date("Y-m-d H:i:s"),
                        "status" => "pending",
                        "ip_hash" => hash("sha256", ($_SERVER["REMOTE_ADDR"] ?? "") . "|alpha-net")
                    ];

                    alpha_save_json($metadataFile, $metadata);

                    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
                    $message = "File uploaded successfully. Thank you.";
                    $messageType = "success";
                } else {
                    $message = "Upload failed. Please check uploads folder permission.";
                    $messageType = "error";
                }
            }
        }
    } elseif ($file["error"] === UPLOAD_ERR_INI_SIZE || $file["error"] === UPLOAD_ERR_FORM_SIZE) {
        $message = "File is larger than the server upload limit.";
        $messageType = "error";
    } else {
        $message = "Please choose a valid file.";
        $messageType = "error";
    }
}

$csrfTokenForForm = $_SESSION["csrf_token"];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AT Space | Secure File Upload</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Segoe UI", Arial, sans-serif; }

        body {
            min-height: 100vh;
            background:
                radial-gradient(circle at top left, rgba(38, 128, 235, 0.38), transparent 34%),
                linear-gradient(135deg, #06142e 0%, #0a2454 48%, #0d6efd 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            color: #101828;
        }

        .shell {
            width: 100%;
            max-width: 980px;
            display: grid;
            grid-template-columns: 0.95fr 1.05fr;
            background: #ffffff;
            border-radius: 28px;
            overflow: hidden;
            box-shadow: 0 34px 90px rgba(0, 0, 0, 0.28);
        }

        .hero {
            background: linear-gradient(160deg, #071d3a, #0d6efd);
            padding: 44px;
            color: #ffffff;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 560px;
        }

        .brand { display: flex; align-items: center; gap: 14px; }
        .brand-logo {
            width: 70px; height: 70px; border-radius: 18px;
            background: rgba(255,255,255,0.14);
            border: 1px solid rgba(255,255,255,0.22);
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; font-weight: 900;
        }

        .brand h1 { font-size: 25px; margin-bottom: 4px; }
        .brand p { font-size: 13px; opacity: 0.82; }

        .hero-main h2 {
            font-size: 38px;
            line-height: 1.15;
            letter-spacing: -0.03em;
            margin-bottom: 18px;
        }

        .hero-main p {
            font-size: 15px;
            line-height: 1.8;
            opacity: 0.86;
            max-width: 360px;
        }

        .hero-note {
            padding: 18px;
            background: rgba(255,255,255,0.12);
            border: 1px solid rgba(255,255,255,0.18);
            border-radius: 18px;
            font-size: 13px;
            line-height: 1.7;
        }

        .form-panel { padding: 44px; }
        .panel-head { margin-bottom: 24px; }
        .panel-head h2 {
            color: #0b1f3a;
            font-size: 28px;
            letter-spacing: -0.02em;
            margin-bottom: 8px;
        }

        .panel-head p { color: #667085; font-size: 14px; line-height: 1.6; }

        .message {
            padding: 14px 15px;
            border-radius: 14px;
            margin-bottom: 20px;
            font-size: 14px;
            font-weight: 700;
        }

        .success { background: #e7f8ee; color: #147a3d; border: 1px solid #bce8cd; }
        .error { background: #fdeaea; color: #b42318; border: 1px solid #f5c2c0; }

        .form-group { margin-bottom: 18px; }
        label {
            display: block;
            font-size: 13px;
            font-weight: 800;
            color: #344054;
            margin-bottom: 8px;
        }

        input[type="email"] {
            width: 100%;
            border: 1px solid #d0d5dd;
            border-radius: 14px;
            padding: 14px 15px;
            font-size: 14px;
            outline: none;
            background: #ffffff;
        }

        input[type="email"]:focus {
            border-color: #0d6efd;
            box-shadow: 0 0 0 4px rgba(13, 110, 253, 0.12);
        }

        .upload-box {
            border: 2px dashed #b7cff5;
            background: #f8fbff;
            border-radius: 20px;
            padding: 28px;
            text-align: center;
            margin-bottom: 18px;
        }

        .upload-icon {
            width: 62px; height: 62px; margin: 0 auto 14px;
            border-radius: 20px; background: #e8f1ff; color: #0d6efd;
            display: flex; align-items: center; justify-content: center;
        }

        .upload-icon svg { width: 30px; height: 30px; }
        input[type="file"] { display: none; }

        .file-label {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 12px 18px;
            background: #ffffff;
            color: #0d47a1;
            border: 1px solid #bad6ff;
            border-radius: 12px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 800;
            margin-bottom: 12px;
        }

        .file-name {
            display: block;
            color: #667085;
            font-size: 13px;
            word-break: break-all;
        }

        .hidden-field {
            position: absolute;
            left: -10000px;
            top: auto;
            width: 1px;
            height: 1px;
            overflow: hidden;
        }

        .btn {
            width: 100%;
            border: none;
            border-radius: 14px;
            padding: 15px 18px;
            font-size: 15px;
            font-weight: 900;
            color: #ffffff;
            background: linear-gradient(135deg, #0d6efd, #084298);
            cursor: pointer;
            box-shadow: 0 14px 28px rgba(13, 110, 253, 0.28);
        }

        .info {
            margin-top: 18px;
            padding: 15px;
            background: #f2f6fc;
            border-radius: 14px;
            color: #475467;
            font-size: 13px;
            line-height: 1.7;
        }

        @media (max-width: 860px) {
            .shell { grid-template-columns: 1fr; }
            .hero { min-height: auto; gap: 32px; }
        }

        @media (max-width: 520px) {
            body { padding: 14px; }
            .hero, .form-panel { padding: 26px; }
            .hero-main h2 { font-size: 30px; }
        }
    </style>
</head>
<body>

<div class="shell">
    <section class="hero">
        <div class="brand">
            <div class="brand-logo"><img src="logo.svg" width="50" alt="AT Space"></div>
            <div>
                <h1>AT Space</h1>
                <p>Simple File Upload</p>
            </div>

        </div>

        <div class="hero-main">
            <h2>Submit your files securely.</h2>
            <p>Upload your documents, images or ZIP files. Admin team will review the submitted file after upload.</p>
        </div>

        <div class="hero-note">
            <strong>Supported:</strong> JPG, PNG, WEBP, PDF, DOC, DOCX, ZIP, TXT<br>
            <strong>Maximum file size:</strong> 20MB
        </div>
    </section>

    <section class="form-panel">
        <div class="panel-head">
            <h2>Upload File</h2>
            <p>Enter your email and upload your file.</p>
        </div>

        <?php if ($message): ?>
            <div class="message <?php echo alpha_clean($messageType); ?>">
                <?php echo alpha_clean($message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo alpha_clean($csrfTokenForForm); ?>">

            <div class="hidden-field">
                <label>Website</label>
                <input type="text" name="website" tabindex="-1" autocomplete="off">
            </div>

            <div class="form-group">
                <label>Email Address</label>
                <input type="email" name="email" placeholder="example@domain.com" required>
            </div>

            <div class="upload-box">
                <div class="upload-icon">
                    <svg viewBox="0 0 24 24" fill="none">
                        <path d="M12 16V4M12 4L7 9M12 4L17 9" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M20 16.5V18C20 19.1 19.1 20 18 20H6C4.9 20 4 19.1 4 18V16.5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                </div>

                <label for="file" class="file-label">Choose File</label>
                <input type="file" name="file" id="file" required>

                <span class="file-name" id="fileName">No file selected</span>
            </div>

            <button class="btn" type="submit">Submit File</button>
        </form>
    </section>
</div>

<script>
    const fileInput = document.getElementById("file");
    const fileName = document.getElementById("fileName");

    fileInput.addEventListener("change", function () {
        fileName.textContent = this.files.length > 0 ? this.files[0].name : "No file selected";
    });
</script>

</body>
</html>
