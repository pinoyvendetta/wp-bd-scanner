#!/usr/bin/env python3
"""
WP Backdoor Scanner (wpbdscanner.py)
Deep recursive scanner for WordPress backdoors, PHP shells, and malware.
Minimizes false positives via multi-indicator scoring + optional
WordPress.org plugin checksum verification.
Compatible with Python 3.6+
"""

import argparse
import base64
import hashlib
import io
import json
import math
import os
import re
import sys
import tarfile
import time
import zipfile
import zlib
import concurrent.futures
import threading
from pathlib import Path
from datetime import datetime

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
    from urllib.parse import unquote
except ImportError:
    from urllib2 import urlopen, Request, URLError, HTTPError  # type: ignore
    from urllib import unquote  # type: ignore

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    C_RED     = Fore.RED + Style.BRIGHT
    C_GREEN   = Fore.GREEN + Style.BRIGHT
    C_YELLOW  = Fore.YELLOW + Style.BRIGHT
    C_CYAN    = Fore.CYAN + Style.BRIGHT
    C_MAGENTA = Fore.MAGENTA + Style.BRIGHT
    C_BLUE    = Fore.BLUE + Style.BRIGHT
    C_WHITE   = Fore.WHITE + Style.BRIGHT
    C_DIM     = Style.DIM
    C_RESET   = Style.RESET_ALL
    C_BG_RED  = Back.RED + Fore.WHITE + Style.BRIGHT
except ImportError:
    C_RED = C_GREEN = C_YELLOW = C_CYAN = C_MAGENTA = C_BLUE = C_WHITE = C_DIM = C_RESET = C_BG_RED = ""

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PHP_EXTENSIONS = {
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phps", ".phar", ".inc", ".module", ".theme",
    # Rare / obfuscated PHP extensions often used by shells
    ".pht", ".phtm", ".pgif", ".php~", ".php.bak", ".php.old",
    ".php.save", ".php.swp", ".php.suspected",
}

# Non-PHP files that can hide PHP or malicious config
DISGUISE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".webp", ".svg", ".bmp",
    ".pdf", ".css", ".txt", ".log", ".dat", ".tmp", ".bak", ".old",
    ".htaccess", ".user.ini", ".ini", ".conf", ".config",
    ".html", ".htm", ".shtml", ".js", ".mjs", ".cjs", ".json", ".xml",
    ".map",  # source maps
}

# Frontend assets: only checked for embedded PHP (disguise), NOT PHP heuristics
# (avoids RegExp.exec / eval / minified-line false positives in jQuery, Elementor, etc.)
FRONTEND_ASSET_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".css", ".map", ".ts", ".tsx", ".jsx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
}

# Archives to open and inspect for embedded PHP / shells
ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",
    ".rar", ".7z", ".cab",
}

# Exact filenames always scanned
ALWAYS_SCAN_NAMES = {
    ".htaccess", ".user.ini", ".htpasswd", "wp-config.php",
    "xmlrpc.php", "install.php", "setup.php",
}

MAX_FILE_SIZE = 8 * 1024 * 1024
MAX_ARCHIVE_MEMBER_SIZE = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBERS_SCAN = 40
MIN_ENTROPY_SUSPICIOUS = 5.2
INCLUDE_NO_EXTENSION = True  # files with no extension (common for dropped shells)

# Paths / library folders that legitimately use crypto, eval-like constructs, etc.
# Heuristic weight is heavily reduced inside these.
KNOWN_LIB_PATH_FRAGMENTS = (
    "/phpseclib/",
    "/vendor/",
    "/node_modules/",
    "/composer/",
    "/tcpdf/",
    "/dompdf/",
    "/phpmailer/",
    "/guzzlehttp/",
    "/symfony/",
    "/monolog/",
    "/elfinder/",
    "/wp-file-manager/lib/",
    "/file-manager/lib/",
    "/tus/",
    "/jetpack_vendor/",
    "/google-site-kit/third-party/",
    "/woocommerce/packages/",
    "/elementor/core/",
    "/wordfence/",
    "/sucuri/",
    "/wp-includes/",
    "/wp-admin/",
    "/simplepie/",
    "/id3/",
    "/requests/",
    "/html-api/",
    "/rest-api/",
    "/sodium_compat/",
    "/Text/Diff/",
    "/IXR/",
    "/PHPMailer/",
    "/languages/",          # GlotPress .l10n.php translation arrays
    "/elementor-pro/",
    "/elementor/assets/",
    "/oceanwp/assets/",
    "/oceanwp/inc/",
)
KNOWN_SIGNATURES = [
    (r"FilesMan\s+version", "FilesMan webshell", 10),
    (r"WSO\s*(?:shell|by)", "WSO (Web Shell by Orb)", 10),
    (r"\$auth_pass\s*=\s*['\"][0-9a-f]{32}['\"]", "WSO-style password hash", 9),
    (r"b374k", "b374k webshell", 10),
    (r"c99shell|r57shell|r57\s*shell", "c99/r57 classic shell", 10),
    (r"ALFA_DATA|Alfa\s*Team|alfacgiapi", "Alfa Team shell", 10),
    (r"ShellBOT|ConnectBackShell|w4ck1ng", "Known shell identifiers", 9),
    (r"MagelangCyber|3xp1r3|FaTaLisTiCz", "Known malware group signatures", 9),
    (r"wp-vcd|class\.theme-modules\.php", "WP-VCD malware family", 10),
    (r"\$sh3llColor|SHELL_PASSWORD|private\s+Shell\s+by", "Generic shell branding", 8),
    (r"eval\s*\(\s*base64_decode\s*\(\s*['\"][A-Za-z0-9+/=]{40,}", "Classic eval+base64 backdoor", 9),
    (r"eval\s*\(\s*base64_decode\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", "eval+base64 of user input", 10),
    (r"eval\s*\(\s*gzinflate\s*\(\s*base64_decode", "eval+gzinflate+base64 chain", 9),
    (r"eval\s*\(\s*gzuncompress\s*\(\s*base64_decode", "eval+gzuncompress+base64 chain", 9),
    (r"eval\s*\(\s*str_rot13\s*\(\s*base64_decode", "eval+rot13+base64 chain", 9),
    (r"@?assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", "assert() backdoor", 9),
    (r"@?eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)", "Direct eval($_REQUEST) backdoor", 10),
    # Word-boundary + no method call: avoid curl_exec, mysql->exec, PDO::exec
    (r"(?<!->)(?<!::)\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST)", "Command exec via user input", 10),
    (r"preg_replace\s*\(\s*['\"]/.*/e['\"]", "preg_replace /e (code execution)", 8),
    (r"create_function\s*\(\s*['\"].*['\"].*\$_(?:GET|POST|REQUEST)", "create_function backdoor", 8),
    (r"file_put_contents\s*\([^,]+,\s*\$_(?:POST|GET|REQUEST|FILES)", "Remote file write via user input", 8),
    (r"chr\s*\(\s*101\s*\)\s*\.\s*chr\s*\(\s*118\s*\)\s*\.\s*chr\s*\(\s*97\s*\)\s*\.\s*chr\s*\(\s*108\s*\)", "chr() assembled 'eval'", 8),
    (r"['\"]ev['\"]\s*\.\s*['\"]al['\"]", "String-concatenated 'eval'", 7),
    # php://input only when paired with eval/assert-style use (signature is weak alone)
    (r"(?:eval|assert|include|require|file_put_contents|fwrite)\s*\([^;]*php://input", "php://input used with code execution", 9),
    (r"auto_prepend_file|auto_append_file", "auto_prepend/append abuse", 7),
]

# Malicious / suspicious .htaccess and .user.ini patterns
HTACCESS_SIGNATURES = [
    (r"(?:php_value|php_flag)\s+auto_(?:prepend|append)_file", "htaccess auto_prepend/append", 10),
    (r"auto_prepend_file\s*=|auto_append_file\s*=", "user.ini auto_prepend/append", 10),
    (r"AddHandler\s+application/x-httpd-php", "htaccess AddHandler PHP on non-php", 8),
    (r"AddType\s+application/x-httpd-php", "htaccess AddType PHP on non-php", 8),
    (r"SetHandler\s+application/x-httpd-php", "htaccess SetHandler PHP", 8),
    (r"RewriteRule\s+.*\.(?:jpg|jpeg|png|gif|css|txt|pdf).*\$1\s*\[.*L", "htaccess rewrite image→script", 7),
    (r"<FilesMatch\s+[\"'].*\.(?:jpg|png|gif|css|txt)", "htaccess FilesMatch on assets", 5),
    (r"php_value\s+engine\s+on", "htaccess force PHP engine on", 6),
]

HEURISTIC_PATTERNS = [
    (r"base64_decode\s*\(", "base64_decode()", 2),
    (r"gzinflate\s*\(|gzuncompress\s*\(|gzdecode\s*\(", "gzinflate/gzuncompress", 2),
    (r"str_rot13\s*\(", "str_rot13()", 2),
    (r"strrev\s*\(", "strrev()", 1),
    (r"\beval\s*\(", "eval()", 3),
    # assert() alone is common for static analysis (PHPStan); low weight
    (r"\bassert\s*\(", "assert()", 1),
    # Avoid matching curl_exec, ->exec(, ::exec(
    (r"(?<!->)(?<!::)\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(", "Command execution function", 3),
    (r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", "User input superglobal", 1),
    (r"@\s*(?:eval|assert|include|require|system|shell_exec)\s*\(", "Error-suppressed dangerous call", 3),
    # goto is used legitimately in WP core UTF-8 / HTML parsers — low weight
    (r"goto\s+[a-zA-Z_][\w]*;", "goto obfuscation", 1),
]

HEX_ESCAPE_PATTERN = (r"\\x[0-9a-fA-F]{2}", "Hex-encoded characters", 1)

# Do NOT match normal WP core names like class-wp-*.php
SUSPICIOUS_NAMES = re.compile(
    r"(?:^|[^a-z0-9])(?:shell|c99|r57|wso|b374k|alfa|backdoor|cmd|rootkit|"
    r"wp-tmp|wp-vcd|webshell|phpshell|c100|r99)(?:[^a-z0-9]|$)",
    re.I
)

# Only flag PHP in *content* cache/upload dirs, not library folders named Cache
FORBIDDEN_PHP_PATHS = (
    "/wp-content/uploads/",
    "/wp-content/cache/",
    "/wp-content/upgrade/",
    "/wp-content/backup",
    "/wp-content/boost-cache/",
    "/wp-content/w3tc-config/",
    "/wp-content/et-cache/",
    "/wp-content/litespeed/",
)

IMAGE_MAGIC = (
    b"\xff\xd8\xff",
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a", b"GIF89a",
    b"RIFF",
    b"%PDF",
    b"\x00\x00\x01\x00",
)

# Cache for plugin checksums: (slug, version) -> {relpath: sha256}
_CHECKSUM_CACHE = {}
_PLUGIN_VERSION_CACHE = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / float(length)) * math.log(c / float(length), 2) for c in freq.values())


def is_probably_binary(data):
    if not data:
        return False
    sample = data[:2048]
    if b"\x00" in sample:
        return True
    non_printable = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
    return (non_printable / float(len(sample))) > 0.30


def is_known_image_or_binary(data):
    if not data or len(data) < 4:
        return False
    for magic in IMAGE_MAGIC:
        if data.startswith(magic):
            return True
    if data[:4] == b"RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
        return True
    return False


def safe_read(path, max_size=MAX_FILE_SIZE):
    try:
        size = path.stat().st_size
        if size == 0 or size > max_size:
            return None
        with open(path, "rb") as f:
            return f.read()
    except (OSError, IOError):
        return None


# Strong PHP tokens that indicate a backdoor / probe (not doc examples like echo)
_PHP_CODE_TOKENS = re.compile(
    rb"(?:phpinfo|eval|assert|system|shell_exec|passthru|exec|popen|proc_open|"
    rb"base64_decode|gzinflate|gzuncompress|preg_replace|create_function|"
    rb"file_put_contents|fwrite|move_uploaded_file|"
    rb"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES))",
    re.I
)
# Mild tokens OK for images/PDF (real PHP) but NOT enough for .js doc comments
_PHP_MILD_TOKENS = re.compile(
    rb"(?:echo|print|include|require|die\s*\(|exit\s*\()",
    re.I
)


def _php_code_window(data, start_idx, max_len=120):
    """
    Extract a printable PHP code window after a tag, stopping at ?> or binary.
    Handles EXIF/JPEG where binary follows immediately after ?>.
    """
    chunk = data[start_idx:start_idx + max_len]
    # Stop at null or high binary bytes (common after EXIF strings)
    out = bytearray()
    for b in chunk:
        if b == 0 or b > 126:
            break
        if b < 9 or (13 < b < 32):
            break
        out.append(b)
        if len(out) >= 3 and out[-2:] == b"?>":
            break
    return bytes(out)


def has_real_php_payload(content, require_strong=False):
    """
    Detect actual PHP inside non-PHP files (including EXIF/comment injection).

    Strict rules to avoid false positives on compressed image/PDF binary data
    that happens to contain the byte sequence <?= or <?php.

    require_strong=True (for .js/.css docs): only accept PHP that looks like a
    backdoor (eval/system/$_POST/phpinfo/...), not documentation examples
    like <?php echo wp_customize_url(); ?>.
    """
    lower = content.lower()

    # --- <?php  (full open tag) ---
    start = 0
    while True:
        idx = lower.find(b"<?php", start)
        if idx < 0:
            break
        # Window after the tag (skip "<?php")
        after = lower[idx + 5: idx + 5 + 80]
        if not after:
            start = idx + 1
            continue

        # Valid open: whitespace, comment, @, or (
        if after[0:1] not in (b" ", b"\n", b"\r", b"\t", b"/", b"@", b"("):
            if not (after.startswith(b"/*") or after.startswith(b"//")):
                start = idx + 1
                continue

        # Code window stops at ?> or binary (critical for EXIF-injected PHP)
        code = _php_code_window(lower, idx + 5, max_len=100)
        if len(code) < 3:
            start = idx + 1
            continue

        printable = sum(1 for b in code if 32 <= b < 127 or b in (9, 10, 13))
        if printable < len(code) * 0.85:
            start = idx + 1
            continue

        # Strong malware-oriented tokens vs mild (echo/print — common in JS docs)
        strong = bool(_PHP_CODE_TOKENS.search(code))
        mild = bool(_PHP_MILD_TOKENS.search(code)) or bool(
            re.search(rb"[a-zA-Z_][a-zA-Z0-9_]*\s*\(", code)
        )

        if require_strong:
            # .js/.css: only backdoor-style PHP, not <?php echo ... ?> docs
            if strong:
                return True
        else:
            # Images/PDF/EXIF: accept strong or mild real PHP statements
            if strong or mild:
                return True

        start = idx + 1

    # --- <?=  (short echo) ---
    # ONLY accept forms that look like real PHP short-echo, never random binary:
    #   <?=$_GET['x']?>  <?=$var?>  <?=system('id')?>  <?=htmlspecialchars(...)?>
    # Reject: <?=9{SDU...  <?=IGF!...  (JPEG/PDF entropy noise)
    start = 0
    while True:
        idx = lower.find(b"<?=", start)
        if idx < 0:
            break
        code = _php_code_window(lower, idx + 3, max_len=80)
        if len(code) < 3:
            start = idx + 1
            continue
        stripped = code.lstrip(b" \t\n\r")
        if not stripped:
            start = idx + 1
            continue

        printable = sum(1 for b in code if 32 <= b < 127 or b in (9, 10, 13))
        if printable < len(code) * 0.90:
            start = idx + 1
            continue

        first = stripped[0:1]
        # 1) Variable: <?=$foo?> or <?=$_GET[...]?>
        if first == b"$":
            # Must look like $ident ...
            if re.match(rb"\$[a-zA-Z_][a-zA-Z0-9_]*", stripped):
                return True
        # 2) Known PHP function call: <?=system(...);?> / <?=phpinfo();?>
        elif _PHP_CODE_TOKENS.search(stripped) or _PHP_MILD_TOKENS.search(stripped):
            if re.search(rb"[a-zA-Z_][a-zA-Z0-9_]*\s*\(", stripped):
                return True
        # 3) Quoted string only if closed tag present (rare, still risky)
        elif first in (b'"', b"'") and b"?>" in code:
            return True
        # Digits / random identifiers (<?=9{... <?=IGF!...) → ignore

        start = idx + 1

    # --- <script language="php"> ---
    if b"<script language=\"php\">" in lower or b"<script language='php'>" in lower:
        return True

    return False


def in_known_lib(path_str):
    p = path_str.replace("\\", "/").lower()
    return any(frag in p for frag in KNOWN_LIB_PATH_FRAGMENTS)


def is_benign_protection_stub(text, path):
    """
    Common safe stubs WordPress plugins place in uploads/cache/logs:
      - index.php that only sends 404 headers
      - *.log.php / guard files that only die() or exit
    """
    # Strip BOM / leading whitespace
    cleaned = text.strip().lstrip("\ufeff")
    # Remove comments for a rough size check
    no_comments = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.S)
    no_comments = re.sub(r"//[^\n]*", "", no_comments)
    no_comments = re.sub(r"#[^\n]*", "", no_comments)
    compact = re.sub(r"\s+", " ", no_comments).strip()

    # Very small PHP files that only protect directories
    if len(compact) > 400:
        return False

    name = path.name.lower()

    # Classic silence / die guards
    if re.match(r"^<\?php\s*(?:die|exit)\s*\(\s*\)\s*;?\s*(?://.*)?(?:\?>)?\s*$", compact, re.I):
        return True
    if "die();" in compact.lower() and "eval" not in compact.lower() and "base64" not in compact.lower():
        if len(compact) < 200:
            return True

    # index.php 404 protectors (BackWPup, many cache plugins, etc.)
    if name == "index.php" or name.endswith(".php"):
        has_404 = (
            "404" in compact
            and ("header" in compact.lower() or "status" in compact.lower())
        )
        dangerous = any(
            k in compact.lower()
            for k in ("eval", "assert", "base64_decode", "shell_exec", "system(",
                      "passthru", "preg_replace", "$_get", "$_post", "$_request",
                      "file_put", "fwrite", "curl_exec")
        )
        if has_404 and not dangerous and len(compact) < 350:
            return True

    # Empty or near-empty silence files: <?php // silence is golden
    if re.match(r"^<\?php\s*(?://.*)?(?:\?>)?\s*$", compact, re.I | re.S):
        return True
    if "silence is golden" in compact.lower():
        return True

    return False


def find_match_lines(text, pattern, max_lines=3, max_len=120):
    """Return up to max_lines of (lineno, truncated_line) matching pattern."""
    hits = []
    try:
        rx = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error:
        return hits
    for i, line in enumerate(text.splitlines(), 1):
        if rx.search(line):
            snippet = line.strip()
            if len(snippet) > max_len:
                snippet = snippet[:max_len] + "..."
            hits.append((i, snippet))
            if len(hits) >= max_lines:
                break
    # If multiline match only, show first line of file region
    if not hits and rx.search(text):
        m = rx.search(text)
        if m:
            start = text[:m.start()].count("\n") + 1
            line = text.splitlines()[start - 1].strip() if start <= len(text.splitlines()) else m.group(0)[:max_len]
            if len(line) > max_len:
                line = line[:max_len] + "..."
            hits.append((start, line))
    return hits


# ---------------------------------------------------------------------------
# Selective multi-encoding decoder (prefix only – low noise)
# ---------------------------------------------------------------------------
# Strong markers that, once decoded, strongly indicate a shell/backdoor
_DECODED_MALWARE_MARKERS = re.compile(
    r"(?:eval\s*\(|assert\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|"
    r"exec\s*\(|popen\s*\(|proc_open\s*\(|preg_replace\s*\([^)]*/e|"
    r"create_function\s*\(|FilesMan|WSO\s*(?:shell|by)|b374k|c99shell|"
    r"r57shell|ALFA_DATA|wp-vcd|\$auth_pass\s*=|base64_decode\s*\(\s*\$_|"
    r"gzinflate\s*\(\s*base64_decode|move_uploaded_file\s*\()",
    re.I
)

_PHP_TAG_RE = re.compile(r"<\?(?:php|=)|<script\s+language\s*=\s*[\"']php[\"']", re.I)


def _safe_b64_decode(s):
    """Try standard and url-safe base64; return bytes or None."""
    s = s.strip()
    # pad if needed
    pad = (-len(s)) % 4
    if pad:
        s = s + ("=" * pad)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(s, validate=False)
        except Exception:
            continue
    return None


def _try_zlib_variants(data):
    """Try common PHP gzip/deflate wrappers used after base64."""
    results = []
    for wbits in (16 + zlib.MAX_WBITS,   # gzip
                  -zlib.MAX_WBITS,       # raw deflate / gzinflate style
                  zlib.MAX_WBITS):       # zlib header
        try:
            results.append(zlib.decompress(data, wbits))
        except Exception:
            pass
    # also try without window bits (some payloads)
    try:
        results.append(zlib.decompress(data))
    except Exception:
        pass
    return results


def _rot13(s):
    try:
        return s.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
    except Exception:
        return s


def try_selective_decode(text, max_candidates=6, prefix_len=3500):
    """
    Find a few long encoded-looking strings, decode only a prefix of each,
    and check whether the decoded fragment looks like a PHP shell.

    Returns list of dicts:
      { "method": str, "snippet": str, "score_boost": int }
    """
    if not text or len(text) < 40:
        return []

    candidates = []

    # 1. Base64-like strings (40+ chars – short pure payloads still caught)
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        candidates.append(("b64", m.group(0)[:prefix_len]))
        if len(candidates) >= max_candidates:
            break

    # 2. Long pure-hex strings (sometimes used)
    if len(candidates) < max_candidates:
        for m in re.finditer(r"(?:[0-9a-fA-F]{2}){40,}", text):
            candidates.append(("hex", m.group(0)[:prefix_len]))
            if len(candidates) >= max_candidates:
                break

    # 3. Very long single lines (common in obfuscated one-liners)
    if len(candidates) < max_candidates:
        for line in text.splitlines():
            line = line.strip()
            if len(line) > 300 and re.search(r"[A-Za-z0-9+/=]{40,}", line):
                # extract the longest base64-ish run inside the line
                mm = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", line)
                if mm:
                    candidates.append(("b64-line", mm.group(0)[:prefix_len]))
                    if len(candidates) >= max_candidates:
                        break

    findings = []
    seen = set()

    for kind, raw in candidates:
        # skip near-duplicates
        key = raw[:80]
        if key in seen:
            continue
        seen.add(key)

        decoded_texts = []

        if kind in ("b64", "b64-line"):
            raw_bytes = _safe_b64_decode(raw)
            if raw_bytes:
                # plain base64
                try:
                    decoded_texts.append(("base64", raw_bytes.decode("utf-8", errors="replace")))
                except Exception:
                    decoded_texts.append(("base64", raw_bytes.decode("latin-1", errors="replace")))
                # base64 + zlib/gzinflate variants
                for inflated in _try_zlib_variants(raw_bytes):
                    try:
                        decoded_texts.append(("base64+gz", inflated.decode("utf-8", errors="replace")))
                    except Exception:
                        try:
                            decoded_texts.append(("base64+gz", inflated.decode("latin-1", errors="replace")))
                        except Exception:
                            pass

        elif kind == "hex":
            try:
                # take even length
                h = raw[: (len(raw) // 2) * 2]
                raw_bytes = bytes(int(h[i:i+2], 16) for i in range(0, min(len(h), prefix_len), 2))
                decoded_texts.append(("hex", raw_bytes.decode("utf-8", errors="replace")))
            except Exception:
                pass

        # Also try rot13 on the original candidate (sometimes layered)
        rot = _rot13(raw[:2000])
        if rot != raw[:2000]:
            decoded_texts.append(("rot13", rot))

        # urldecode
        try:
            ud = unquote(raw[:2000])
            if ud != raw[:2000] and len(ud) > 20:
                decoded_texts.append(("urldecode", ud))
        except Exception:
            pass

        for method, dec in decoded_texts:
            if not dec or len(dec) < 15:
                continue
            # Does the decoded fragment look malicious?
            has_php = bool(_PHP_TAG_RE.search(dec))
            has_marker = bool(_DECODED_MALWARE_MARKERS.search(dec))
            if has_marker or (has_php and re.search(
                    r"(?:eval|system|shell_exec|passthru|assert|base64_decode|gzinflate)\s*\(",
                    dec, re.I)):
                # Build a short readable snippet
                snippet = dec.strip().replace("\n", " ").replace("\r", "")
                if len(snippet) > 140:
                    snippet = snippet[:140] + "..."
                boost = 9 if has_marker else 6
                findings.append({
                    "method": method,
                    "snippet": snippet,
                    "score_boost": boost,
                })
                # one solid hit per file is enough to raise the alarm
                if len(findings) >= 2:
                    return findings

    return findings


# ---------------------------------------------------------------------------
# WordPress.org checksum verification
# ---------------------------------------------------------------------------
def _http_get_json(url, timeout=12):
    try:
        req = Request(url, headers={"User-Agent": "WPBDScanner/1.1"})
        resp = urlopen(req, timeout=timeout)
        return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def detect_plugin_slug_and_version(file_path, scan_root):
    """
    Given a path under .../plugins/<slug>/..., return (slug, version) or (None, None).
    Version is read from the main plugin PHP file header when possible.
    """
    try:
        full = str(file_path.resolve())
        root = str(scan_root.resolve())
    except Exception:
        return None, None

    # Find /plugins/<slug>/
    norm = full.replace("\\", "/")
    idx = norm.lower().find("/plugins/")
    if idx < 0:
        return None, None
    rest = norm[idx + len("/plugins/"):]
    parts = rest.split("/")
    if not parts or not parts[0]:
        return None, None
    slug = parts[0]

    if slug in _PLUGIN_VERSION_CACHE:
        return slug, _PLUGIN_VERSION_CACHE[slug]

    # Try to read Version: from main plugin file
    plugin_dir = Path(norm[:idx + len("/plugins/")] + slug)
    version = None
    candidates = [
        plugin_dir / (slug + ".php"),
        plugin_dir / "plugin.php",
        plugin_dir / "index.php",
    ]
    # also any php in root of plugin
    try:
        for p in plugin_dir.glob("*.php"):
            candidates.append(p)
    except Exception:
        pass

    ver_re = re.compile(r"^\s*\*\s*Version:\s*([0-9][0-9a-zA-Z._-]*)", re.I | re.M)
    ver_re2 = re.compile(r"^\s*Version:\s*([0-9][0-9a-zA-Z._-]*)", re.I | re.M)

    for cand in candidates:
        try:
            if not cand.is_file():
                continue
            text = cand.read_text(encoding="utf-8", errors="ignore")[:4000]
            m = ver_re.search(text) or ver_re2.search(text)
            if m:
                version = m.group(1).strip()
                break
        except Exception:
            continue

    # Fallback: readme.txt Stable tag
    if not version:
        readme = plugin_dir / "readme.txt"
        try:
            if readme.is_file():
                text = readme.read_text(encoding="utf-8", errors="ignore")[:3000]
                m = re.search(r"Stable tag:\s*([0-9][0-9a-zA-Z._-]*)", text, re.I)
                if m:
                    version = m.group(1).strip()
        except Exception:
            pass

    _PLUGIN_VERSION_CACHE[slug] = version
    return slug, version


def fetch_plugin_checksums(slug, version):
    if not slug or not version:
        return None
    key = (slug, version)
    if key in _CHECKSUM_CACHE:
        return _CHECKSUM_CACHE[key]

    url = "https://downloads.wordpress.org/plugin-checksums/%s/%s.json" % (slug, version)
    data = _http_get_json(url)
    files_map = {}
    if data and isinstance(data, dict) and "files" in data:
        for rel, hashes in data["files"].items():
            if isinstance(hashes, dict) and "sha256" in hashes:
                files_map[rel.replace("\\", "/")] = hashes["sha256"].lower()
    _CHECKSUM_CACHE[key] = files_map if files_map else None
    return _CHECKSUM_CACHE[key]


def verify_against_wordpress_org(file_path, scan_root, file_data):
    """
    Returns one of:
      ('match', slug, version)   – file matches official checksum
      ('mismatch', slug, version) – official checksums exist but hash differs
      ('unknown', slug, version) – no checksums available / not a.org plugin
      (None, None, None)         – not under plugins/
    """
    slug, version = detect_plugin_slug_and_version(file_path, scan_root)
    if not slug:
        return None, None, None

    checksums = fetch_plugin_checksums(slug, version) if version else None
    if not checksums:
        return "unknown", slug, version

    # Relative path inside the plugin package
    try:
        full = str(file_path.resolve()).replace("\\", "/")
        marker = "/plugins/" + slug + "/"
        idx = full.lower().find(marker.lower())
        if idx < 0:
            return "unknown", slug, version
        rel = full[idx + len(marker):]
    except Exception:
        return "unknown", slug, version

    official = checksums.get(rel)
    if not official:
        # file not in official package (extra file) → treat as mismatch/suspicious
        return "mismatch", slug, version

    local_hash = hashlib.sha256(file_data).hexdigest().lower()
    if local_hash == official:
        return "match", slug, version
    return "mismatch", slug, version


# ---------------------------------------------------------------------------
# Archive inspection (zip / tar family; rar/7z best-effort)
# ---------------------------------------------------------------------------
def _is_php_like_name(name):
    n = name.lower().replace("\\", "/")
    base = n.rsplit("/", 1)[-1]
    if base in ALWAYS_SCAN_NAMES:
        return True
    for ext in PHP_EXTENSIONS:
        if base.endswith(ext):
            return True
    # extension-less member with suspicious name
    if "." not in base and SUSPICIOUS_NAMES.search(base):
        return True
    return False


def _scan_member_bytes(name, data):
    """Return (score_boost, findings_list, snippets_list) for one archive member."""
    findings = []
    snippets = []
    score = 0
    if not data:
        return 0, findings, snippets

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    # Strong signatures inside member
    for pattern, desc, weight in KNOWN_SIGNATURES:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            score += weight
            findings.append("archive:%s → %s" % (name, desc))
            for ln, snip in find_match_lines(text, pattern, max_lines=1):
                snippets.append("%s:L%d: %s" % (name, ln, snip))

    # Real PHP payload in non-php member name
    if has_real_php_payload(data) and not _is_php_like_name(name):
        score += 10
        findings.append("archive:%s → PHP payload inside non-PHP member" % name)

    # Selective decode on member text
    if text and score < 15:
        try:
            for dh in try_selective_decode(text, max_candidates=3, prefix_len=2000):
                score += dh["score_boost"]
                findings.append("archive:%s → decoded(%s) malware" % (name, dh["method"]))
                snippets.append("%s:decoded(%s): %s" % (name, dh["method"], dh["snippet"][:100]))
        except Exception:
            pass

    return score, findings, snippets


def inspect_archive(path, data):
    """
    Open zip/tar archives and scan embedded members for PHP shells.
    Returns (extra_score, findings, snippets) or (0, [], []) on failure/unsupported.
    """
    extra_score = 0
    findings = []
    snippets = []
    name_lower = path.name.lower()
    members_checked = 0

    # ----- ZIP -----
    if name_lower.endswith(".zip") or (len(data) >= 4 and data[:2] == b"PK"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir() or members_checked >= MAX_ARCHIVE_MEMBERS_SCAN:
                        continue
                    member = info.filename
                    if info.file_size > MAX_ARCHIVE_MEMBER_SIZE:
                        continue
                    # Always check PHP-like names; also check a few others for disguise
                    interesting = _is_php_like_name(member) or any(
                        member.lower().endswith(ext) for ext in (".jpg", ".png", ".gif", ".txt", ".dat")
                    )
                    if not interesting:
                        continue
                    members_checked += 1
                    try:
                        raw = zf.read(info)
                    except Exception:
                        continue
                    sc, fd, sn = _scan_member_bytes(member, raw)
                    if sc:
                        extra_score += sc
                        findings.extend(fd)
                        snippets.extend(sn)
                        if extra_score >= 20:
                            break
        except Exception:
            pass
        return extra_score, findings, snippets

    # ----- TAR / TAR.GZ / TAR.BZ2 / TAR.XZ -----
    tar_like = any(name_lower.endswith(ext) for ext in (
        ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".gz", ".bz2", ".xz"
    ))
    if tar_like:
        try:
            # gzip/bz2 single-file compression of a tar, or plain tar
            mode = "r:*"  # let tarfile auto-detect
            with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
                for member in tf.getmembers():
                    if not member.isfile() or members_checked >= MAX_ARCHIVE_MEMBERS_SCAN:
                        continue
                    if member.size > MAX_ARCHIVE_MEMBER_SIZE:
                        continue
                    mname = member.name
                    interesting = _is_php_like_name(mname) or any(
                        mname.lower().endswith(ext) for ext in (".jpg", ".png", ".gif", ".txt", ".dat")
                    )
                    if not interesting:
                        continue
                    members_checked += 1
                    try:
                        f = tf.extractfile(member)
                        if f is None:
                            continue
                        raw = f.read(MAX_ARCHIVE_MEMBER_SIZE)
                    except Exception:
                        continue
                    sc, fd, sn = _scan_member_bytes(mname, raw)
                    if sc:
                        extra_score += sc
                        findings.extend(fd)
                        snippets.extend(sn)
                        if extra_score >= 20:
                            break
        except Exception:
            pass
        return extra_score, findings, snippets

    # ----- RAR / 7z (optional external tools; otherwise name-only note) -----
    if name_lower.endswith(".rar") or name_lower.endswith(".7z"):
        # Without rarfile/py7zr we cannot parse contents reliably.
        # Still flag if the archive itself has a highly suspicious name.
        if SUSPICIOUS_NAMES.search(path.name):
            extra_score += 5
            findings.append("Suspicious archive name (%s) — inspect manually" % path.name)
        return extra_score, findings, snippets

    return 0, [], []


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------
def analyze_file(path, root, _depth=0):
    if _depth > 2:
        return None
    try:
        path_key = str(path.resolve())
    except Exception:
        path_key = str(path)
    with _ANALYZING_LOCK:
        if path_key in _ANALYZING_PATHS:
            return None
        _ANALYZING_PATHS.add(path_key)

    try:
        return _analyze_file_inner(path, root, _depth)
    finally:
        with _ANALYZING_LOCK:
            _ANALYZING_PATHS.discard(path_key)


def _analyze_file_inner(path, root, _depth=0):
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path

    data = safe_read(path)
    if data is None:
        return None

    name_lower = path.name.lower()
    ext = path.suffix.lower()
    # Compound archive extensions
    is_archive = (
        ext in ARCHIVE_EXTENSIONS
        or name_lower.endswith(".tar.gz")
        or name_lower.endswith(".tar.bz2")
        or name_lower.endswith(".tar.xz")
        or name_lower.endswith(".tgz")
        or name_lower.endswith(".tbz2")
        or name_lower.endswith(".txz")
    )
    is_php_ext = ext in PHP_EXTENSIONS
    is_htaccess = name_lower in {".htaccess", ".user.ini"}
    is_frontend_asset = ext in FRONTEND_ASSET_EXTENSIONS
    is_image = is_known_image_or_binary(data) and not is_archive
    is_binary = is_probably_binary(data)
    path_str = str(path).replace("\\", "/").lower()
    lib = in_known_lib(path_str)
    no_ext = (ext == "" and not name_lower.startswith("."))

    # Fast skip: pure images / pure binary non-PHP with no real PHP payload
    # (archives are handled separately below)
    disguise_bonus = 0
    if not is_archive and (is_image or (is_binary and not is_php_ext and not is_htaccess and not no_ext)):
        if not has_real_php_payload(data):
            return None
        disguise_bonus = 12
    # Frontend assets (.js/.css/.map): only report if *strong* PHP backdoor
    # is embedded — not documentation examples like <?php echo wp_customize_url(); ?>
    elif is_frontend_asset:
        if has_real_php_payload(data, require_strong=True):
            disguise_bonus = 12
        else:
            return None

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    # Benign directory-protection / log-guard stubs → never report
    if is_php_ext and is_benign_protection_stub(text, path):
        return None

    # Extension-less pure binary with no PHP → skip
    if no_ext and is_binary and not has_real_php_payload(data) and not is_archive:
        return None

    findings = []
    snippets = []  # list of "L123: code..."
    score = disguise_bonus
    matched_sigs = []
    has_code_signal = False  # True if SIG or HEUR matched (not just location)

    if disguise_bonus:
        findings.append("%s[DISGUISE]%s Real PHP payload inside non-PHP / image file" % (C_RED, C_RESET))
        has_code_signal = True
        # Show where PHP tag was found
        for marker in (b"<?php", b"<?=", b"<script language=\"php\">"):
            idx = data.lower().find(marker)
            if idx >= 0:
                line_no = data[:idx].count(b"\n") + 1
                try:
                    window = data[idx:idx + 80].decode("utf-8", errors="replace").replace("\n", " ")
                except Exception:
                    window = repr(data[idx:idx + 40])
                if len(window) > 100:
                    window = window[:100] + "..."
                snippets.append("L%d: %s" % (line_no, window))
                break

    # ----- Archive inspection -----
    if is_archive:
        try:
            a_score, a_findings, a_snips = inspect_archive(path, data)
        except Exception:
            a_score, a_findings, a_snips = 0, [], []
        if a_score:
            score += a_score
            has_code_signal = True
            for f in a_findings:
                findings.append("%s[ARCHIVE]%s %s" % (C_RED, C_RESET, f))
                matched_sigs.append(f)
            snippets.extend(a_snips[:4])
        # Archives with no internal hits and no suspicious name → not reported
        if score < 7 and not SUSPICIOUS_NAMES.search(path.name):
            return None

    # 1. High-confidence signatures
    # Skip pure images and frontend assets (.js/.css/...) — PHP patterns there are noise
    # (RegExp.exec, JS eval, minified bundles). Still detect real PHP-in-JS via disguise.
    if not is_image and not is_frontend_asset and text:
        for pattern, desc, weight in KNOWN_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                if lib and weight < 8:
                    continue
                score += weight
                matched_sigs.append(desc)
                has_code_signal = True
                findings.append("%s[SIG]%s %s" % (C_RED, C_RESET, desc))
                for ln, snip in find_match_lines(text, pattern):
                    snippets.append("L%d: %s" % (ln, snip))

    # 1b. .htaccess / .user.ini specific rules
    if is_htaccess and text:
        for pattern, desc, weight in HTACCESS_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE):
                score += weight
                matched_sigs.append(desc)
                has_code_signal = True
                findings.append("%s[HTACCESS]%s %s" % (C_RED, C_RESET, desc))
                for ln, snip in find_match_lines(text, pattern):
                    snippets.append("L%d: %s" % (ln, snip))

    # 2. Heuristics (reduced weight inside known libraries)
    # Never apply PHP heuristics to frontend assets
    heur_hits = []
    weight_factor = 0.25 if lib else 1.0

    if not is_image and not is_frontend_asset:
        for pattern, desc, weight in HEURISTIC_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                count = len(matches)
                contrib = int(min(weight * min(count, 3), weight * 3) * weight_factor)
                if contrib > 0:
                    score += contrib
                    has_code_signal = True
                    heur_hits.append("%s×%d" % (desc, count))
                    for ln, snip in find_match_lines(text, pattern, max_lines=2):
                        snippets.append("L%d: %s" % (ln, snip))

        if not is_binary and not lib:
            hex_pat, hex_desc, hex_w = HEX_ESCAPE_PATTERN
            hex_matches = re.findall(hex_pat, text)
            if hex_matches:
                count = len(hex_matches)
                contrib = min(hex_w * min(count, 3), hex_w * 3)
                score += contrib
                has_code_signal = True
                heur_hits.append("%s×%d" % (hex_desc, count))

    if heur_hits:
        label = "lib-heuristics (reduced)" if lib else "HEUR"
        findings.append("%s[%s]%s %s" % (C_YELLOW, label, C_RESET, ", ".join(heur_hits)))

    # 2b. Follow include/require/file_get_contents targets
    if is_php_ext and text and not is_image:
        try:
            i_score, i_findings, i_snips, i_extra = inspect_include_targets(
                path, text, root, lib=lib
            )
        except Exception:
            i_score, i_findings, i_snips, i_extra = 0, [], [], []
        if i_score:
            score += i_score
            has_code_signal = True
            findings.extend(i_findings)
            snippets.extend(i_snips[:4])
        if i_extra:
            with _DISCOVERED_LOCK:
                _DISCOVERED_RESULTS.extend(i_extra)

    # 3. Location — only meaningful together with code signals
    is_forbidden_loc = any(p in path_str for p in FORBIDDEN_PHP_PATHS)
    if is_php_ext and is_forbidden_loc:
        if has_code_signal or disguise_bonus:
            score += 8
            findings.append("%s[LOC]%s PHP file inside uploads/cache/tmp" % (C_RED, C_RESET))
        # else: location alone is NOT enough (avoids index.php / log.php stubs)

    # 4. Filename
    if SUSPICIOUS_NAMES.search(path.name):
        score += 3
        findings.append("%s[NAME]%s Suspicious filename" % (C_YELLOW, C_RESET))

    # 5. Entropy / density (text/PHP only — never on minified JS/CSS)
    ent = entropy(data)
    if (not is_image and not is_binary and not is_frontend_asset and not lib
            and ent >= MIN_ENTROPY_SUSPICIOUS and len(data) > 200):
        if score >= 4 and has_code_signal:
            score += 3
            findings.append("%s[ENTROPY]%s High entropy (%.2f)" % (C_YELLOW, C_RESET, ent))

    if not is_image and not is_binary and not is_frontend_asset and not lib:
        lines = text.splitlines()
        if lines:
            max_line = max(len(l) for l in lines)
            if max_line > 2000 and score >= 3 and has_code_signal:
                score += 2
                findings.append("%s[DENSE]%s Very long line (%d chars)" % (C_YELLOW, C_RESET, max_line))
        b64_long = re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", text)
        if len(b64_long) >= 2 and score >= 3 and has_code_signal:
            score += 2
            findings.append("%s[B64]%s Multiple long base64-like strings" % (C_YELLOW, C_RESET))

    # ---------------------------------------------------------------------------
    # Selective multi-encoding decode (prefix only)
    # Catches payload-only files where the decoder lives elsewhere.
    # Skip frontend assets (base64 in JS bundles is normal).
    # ---------------------------------------------------------------------------
    if not is_image and not is_binary and not is_frontend_asset:
        # Run even on low initial score so pure base64 payload files are caught,
        # but skip heavy library paths unless we already have a signal.
        if (not lib) or has_code_signal or score >= 3:
            try:
                decoded_hits = try_selective_decode(text)
            except Exception:
                decoded_hits = []
            for dh in decoded_hits:
                score += dh["score_boost"]
                has_code_signal = True
                findings.append(
                    "%s[DECODED]%s Suspicious content after %s decode"
                    % (C_RED, C_RESET, dh["method"])
                )
                snippets.append("decoded(%s): %s" % (dh["method"], dh["snippet"]))

    # ---------------------------------------------------------------------------
    # WordPress.org checksum verification (plugins only)
    # ---------------------------------------------------------------------------
    verify_status = None
    v_slug = v_ver = None
    if score >= 5 and "/plugins/" in path_str:
        verify_status, v_slug, v_ver = verify_against_wordpress_org(path, root, data)
        if verify_status == "match":
            findings.append(
                "%s[VERIFIED]%s Matches official WordPress.org checksum (%s v%s)"
                % (C_GREEN, C_RESET, v_slug, v_ver or "?")
            )
            if not any(s for s in matched_sigs if "backdoor" in s.lower() or "webshell" in s.lower()
                       or "eval($_REQUEST" in s or "eval($_POST" in s or "eval($_GET" in s):
                return None
            score = max(score - 15, 3)
        elif verify_status == "mismatch":
            score += 10
            findings.append(
                "%s[MODIFIED]%s Does NOT match official WordPress.org checksum (%s v%s) — file altered or extra"
                % (C_RED, C_RESET, v_slug, v_ver or "?")
            )
        elif verify_status == "unknown" and v_slug:
            findings.append(
                "%s[INFO]%s Plugin '%s' — no checksums available (not on wordpress.org or version %s unknown)"
                % (C_DIM, C_RESET, v_slug, v_ver or "?")
            )

    # ---------------------------------------------------------------------------
    # Optional YARA
    # ---------------------------------------------------------------------------
    if YARA_RULES_PATH and data:
        yara_hits = run_yara_rules(path, YARA_RULES_PATH, data)
        for rule in yara_hits:
            score += 12
            has_code_signal = True
            matched_sigs.append("YARA:" + rule)
            findings.append("%s[YARA]%s Matched rule: %s" % (C_RED, C_RESET, rule))

    # ---------------------------------------------------------------------------
    # Threshold: location-only hits are dropped
    # ---------------------------------------------------------------------------
    # A successful selective-decode hit is treated as a strong signal
    has_decoded_hit = any("[DECODED]" in f for f in findings)

    if score < 7:
        return None

    if not has_code_signal and verify_status != "mismatch" and not disguise_bonus:
        return None

    if score < 10 and not matched_sigs and not disguise_bonus and not has_decoded_hit and verify_status != "mismatch":
        return None

    # WordPress core / known libraries: suppress pure-heuristic noise
    # unless a strong backdoor signature, decoded payload, or checksum mismatch is present
    if lib and not disguise_bonus and verify_status != "mismatch":
        strong = has_decoded_hit or any(
            s for s in matched_sigs
            if any(k in s.lower() for k in (
                "backdoor", "webshell", "eval($_", "command exec via user",
                "eval+base64", "assert() backdoor", "wp-vcd", "filesman", "wso",
            ))
        )
        if not strong:
            return None

    strong_hit = has_decoded_hit or any(
        s for s in matched_sigs
        if any(k in s.lower() for k in (
            "backdoor", "webshell", "eval($_", "command exec via user",
            "eval+base64", "assert() backdoor", "wp-vcd", "filesman", "wso",
        ))
    )

    if score >= 15 or disguise_bonus >= 12:
        risk = "CRITICAL"
        risk_color = C_BG_RED
    elif score >= 11 or strong_hit:
        risk = "HIGH"
        risk_color = C_RED
    else:
        risk = "MEDIUM"
        risk_color = C_YELLOW

    # Dedupe snippets, keep order
    seen = set()
    unique_snips = []
    for s in snippets:
        if s not in seen:
            seen.add(s)
            unique_snips.append(s)

    return {
        "path": str(rel),
        "full_path": str(path),
        "score": score,
        "risk": risk,
        "risk_color": risk_color,
        "findings": findings,
        "snippets": unique_snips[:6],
        "size": len(data),
        "entropy": round(ent, 2),
        "mtime": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
        "verified": verify_status,
    }


# ---------------------------------------------------------------------------
# Include / require / file_get_contents target following
# ---------------------------------------------------------------------------
# Matches: include 'x'; require_once("y"); file_get_contents('z');
# Also: include( ABSPATH . 'file.php' ) is partially handled when a string literal path appears
_INCLUDE_CALL_RE = re.compile(
    r"""(?<!->)(?<!::)\b(?:include|include_once|require|require_once|file_get_contents|readfile|fopen|file|parse_ini_file|highlight_file|show_source)\s*\(\s*(?:['"]([^'"]{1,400})['"]|([A-Za-z0-9+/=]{40,}))""",
    re.I,
)

# Paths that are normal WP includes — don't chase as suspicious
_BORING_INCLUDE_HINTS = (
    "wp-load.php", "wp-blog-header.php", "wp-config.php", "wp-settings.php",
    "wp-admin/", "wp-includes/", "ABSPATH", "WPINC", "template-loader",
)


def _decode_possible_path(s):
    """Try to decode base64/hex/url-encoded path strings."""
    results = [s]
    # base64
    raw = _safe_b64_decode(s)
    if raw:
        try:
            results.append(raw.decode("utf-8", errors="ignore"))
        except Exception:
            pass
        for d in _try_zlib_variants(raw):
            try:
                results.append(d.decode("utf-8", errors="ignore"))
            except Exception:
                pass
    # hex
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}){4,}", s):
        try:
            results.append(bytes.fromhex(s).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    # urldecode
    try:
        u = unquote(s)
        if u != s:
            results.append(u)
    except Exception:
        pass
    return results


def extract_include_targets(text, base_dir, root):
    """
    Return list of existing Path objects referenced by include/require/
    file_get_contents-style calls. Follows relative paths; tries light decoding.
    """
    found = []
    seen = set()
    if not text:
        return found
    base_dir = Path(base_dir)
    root = Path(root)

    for m in _INCLUDE_CALL_RE.finditer(text):
        raw = m.group(1) or m.group(2) or ""
        raw = raw.strip()
        if not raw or len(raw) > 400:
            continue
        # Skip obvious core includes
        low = raw.lower()
        if any(h.lower() in low for h in _BORING_INCLUDE_HINTS):
            continue
        if low.startswith("http://") or low.startswith("https://") or low.startswith("php://"):
            continue

        candidates_str = _decode_possible_path(raw)
        for s in candidates_str:
            s = s.strip().strip("\x00")
            if not s or len(s) > 400:
                continue
            # strip query-like junk
            if "\n" in s or "\r" in s:
                s = s.split("\n", 1)[0].split("\r", 1)[0]
            # Resolve relative to including file, then root
            for base in (base_dir, root):
                try:
                    p = (base / s).resolve()
                except Exception:
                    continue
                try:
                    # Must stay under scan root
                    p.relative_to(root.resolve())
                except Exception:
                    continue
                if not p.is_file():
                    continue
                key = str(p)
                if key in seen:
                    continue
                seen.add(key)
                found.append(p)
                break
    return found


def inspect_include_targets(path, text, root, lib=False):
    """
    Follow include/require/file_get_contents targets.
    Returns (score_boost, findings, snippets, extra_results).
    extra_results: list of full analyze_file dicts for suspicious targets.
    """
    score = 0
    findings = []
    snippets = []
    extra = []
    if lib:
        return 0, findings, snippets, extra

    targets = extract_include_targets(text, path.parent, root)
    if not targets:
        return 0, findings, snippets, extra

    for t in targets[:12]:  # cap
        t_ext = t.suffix.lower()
        t_name = t.name.lower()
        t_str = str(t).replace("\\", "/").lower()
        unusual = (
            t_ext not in PHP_EXTENSIONS
            and t_name not in ALWAYS_SCAN_NAMES
            and t_ext not in {".inc", ".module"}
        )
        in_uploads = any(p in t_str for p in FORBIDDEN_PHP_PATHS)

        # Suspicious: including a non-PHP file, or anything from uploads/cache
        if unusual or in_uploads:
            score += 6
            findings.append(
                "%s[INCLUDE]%s Loads suspicious path: %s"
                % (C_RED, C_RESET, t.name if not unusual else str(t.relative_to(root)) if True else t.name)
            )
            try:
                rel = str(t.relative_to(root))
            except Exception:
                rel = t.name
            findings[-1] = "%s[INCLUDE]%s Loads suspicious path: %s" % (C_RED, C_RESET, rel)
            snippets.append("include → %s" % rel)

            # Analyze the target itself
            try:
                sub = analyze_file(t, root)
            except Exception:
                sub = None
            if sub:
                extra.append(sub)
                score += 4
                findings.append(
                    "%s[INCLUDE]%s Target flagged: %s (%s)"
                    % (C_RED, C_RESET, rel, sub.get("risk", "?"))
                )
            else:
                # Even if target is quiet, peek for PHP payload / high entropy
                try:
                    data = safe_read(t)
                    if data and has_real_php_payload(data):
                        score += 10
                        findings.append(
                            "%s[INCLUDE]%s Target contains embedded PHP: %s"
                            % (C_RED, C_RESET, rel)
                        )
                    elif data and not is_probably_binary(data):
                        # selective decode on included non-php text
                        try:
                            ttext = data.decode("utf-8", errors="ignore")
                            for dh in try_selective_decode(ttext, max_candidates=3):
                                score += dh["score_boost"]
                                findings.append(
                                    "%s[INCLUDE+DECODED]%s %s via %s"
                                    % (C_RED, C_RESET, rel, dh["method"])
                                )
                                snippets.append("include-decoded(%s): %s" % (dh["method"], dh["snippet"][:80]))
                        except Exception:
                            pass
                except Exception:
                    pass
        else:
            # Normal .php include — still analyze if under uploads
            if in_uploads:
                score += 3
                try:
                    rel = str(t.relative_to(root))
                except Exception:
                    rel = t.name
                findings.append("%s[INCLUDE]%s Includes PHP from uploads/cache: %s" % (C_YELLOW, C_RESET, rel))
                try:
                    sub = analyze_file(t, root)
                    if sub:
                        extra.append(sub)
                except Exception:
                    pass

    return score, findings, snippets, extra


# ---------------------------------------------------------------------------
# Scanner engine
# ---------------------------------------------------------------------------
def _file_should_scan(path):
    """Decide whether a path is a candidate for analysis."""
    name = path.name
    name_lower = name.lower()
    ext = path.suffix.lower()

    # Multi-suffix archives: .tar.gz, .tar.bz2, .tar.xz
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if name_lower.endswith(compound):
            return True

    if name_lower in ALWAYS_SCAN_NAMES or name in ALWAYS_SCAN_NAMES:
        return True
    if ext in PHP_EXTENSIONS or ext in DISGUISE_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
        return True
    # Files with no extension (dropped shells, "shell", "x", etc.)
    if INCLUDE_NO_EXTENSION and ext == "" and name and not name.startswith("."):
        return True
    # Dotfiles that are config-like
    if name_lower in {".htaccess", ".user.ini", ".htpasswd"}:
        return True
    return False


def collect_files(root):
    candidates = []
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                d for d in dirnames
                if d not in {".git", "node_modules", ".svn", "__pycache__"}
            ]
            for name in filenames:
                p = Path(dirpath) / name
                try:
                    if path_is_ignored(p, IGNORE_PATTERNS):
                        continue
                    if _file_should_scan(p):
                        candidates.append(p)
                except Exception:
                    continue
    except Exception as e:
        print("%s[!] Error walking directory: %s%s" % (C_RED, e, C_RESET))
    return candidates


def format_elapsed(seconds):
    if seconds < 60:
        return "%.1fs" % seconds
    m = int(seconds // 60)
    s = seconds % 60
    return "%dm %.1fs" % (m, s)


def scan(root, threads):
    global _DISCOVERED_RESULTS
    files = collect_files(root)
    total = len(files)
    print("%s[*] Found %d candidate files. Scanning with %d threads...%s\n" % (C_CYAN, total, threads, C_RESET))

    results = []
    processed = 0
    t0 = time.time()
    with _DISCOVERED_LOCK:
        _DISCOVERED_RESULTS = []

    def worker(path):
        return analyze_file(path, root)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_path = {executor.submit(worker, f): f for f in files}
        for future in concurrent.futures.as_completed(future_to_path):
            processed += 1
            elapsed = time.time() - t0
            if processed % 25 == 0 or processed == total:
                pct = (100.0 * processed / total) if total else 100
                sys.stdout.write(
                    "\r%s  Progress: %d/%d (%.0f%%) | Elapsed: %s%s"
                    % (C_DIM, processed, total, pct, format_elapsed(elapsed), C_RESET)
                )
                sys.stdout.flush()
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception:
                continue

    print()
    # Merge results from followed includes (dedupe by full_path)
    with _DISCOVERED_LOCK:
        extras = list(_DISCOVERED_RESULTS)
        _DISCOVERED_RESULTS = []
    seen_paths = {r["full_path"] for r in results}
    for r in extras:
        if r and r.get("full_path") not in seen_paths:
            results.append(r)
            seen_paths.add(r["full_path"])
    if extras:
        print("%s[*] Followed include/require targets: %d additional finding(s)%s"
              % (C_CYAN, len([e for e in extras if e]), C_RESET))

    return sorted(results, key=lambda x: (-x["score"], x["path"])), time.time() - t0


# ---------------------------------------------------------------------------
# Ignore list / whitelist
# ---------------------------------------------------------------------------
def load_ignore_patterns(path):
    """
    Load ignore patterns from a text file.
    One pattern per line. Empty lines and # comments ignored.
    Patterns match if they appear as a substring of the full path
    (case-insensitive), or as a glob-style suffix when starting with *.
    """
    patterns = []
    if not path:
        return patterns
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    except Exception as e:
        print("%s[!] Could not read ignore file %s: %s%s" % (C_YELLOW, path, e, C_RESET))
    return patterns


def path_is_ignored(path, patterns):
    if not patterns:
        return False
    full = str(path).replace("\\", "/").lower()
    name = Path(path).name.lower()
    for pat in patterns:
        p = pat.replace("\\", "/").lower()
        if p.startswith("*") and name.endswith(p[1:]):
            return True
        if p in full or full.endswith(p) or name == p:
            return True
    return False


# ---------------------------------------------------------------------------
# Optional YARA support
# ---------------------------------------------------------------------------
def run_yara_rules(path, rules_path, data):
    """
    If yara-python is installed and rules_path is set, scan file data.
    Returns list of matching rule names, or [].
    """
    if not rules_path:
        return []
    try:
        import yara  # optional dependency
    except ImportError:
        return []
    try:
        rules = yara.compile(filepath=str(rules_path))
        matches = rules.match(data=data)
        return [m.rule for m in matches]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Export & quarantine
# ---------------------------------------------------------------------------
def _strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s) if isinstance(s, str) else s


def export_json(results, root, elapsed, out_path):
    payload = {
        "scanner": "wpbdscanner",
        "version": "1.3",
        "target": str(root),
        "elapsed_seconds": round(elapsed, 2),
        "found": len(results),
        "results": [],
    }
    for r in results:
        payload["results"].append({
            "risk": r["risk"],
            "score": r["score"],
            "path": r["path"],
            "full_path": r["full_path"],
            "size": r["size"],
            "entropy": r["entropy"],
            "mtime": r["mtime"],
            "findings": [_strip_ansi(f) for f in r.get("findings") or []],
            "snippets": r.get("snippets") or [],
            "verified": r.get("verified"),
        })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print("%s[*] JSON report written: %s%s" % (C_GREEN, out_path, C_RESET))


def export_csv(results, out_path):
    import csv
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["risk", "score", "path", "full_path", "size", "entropy", "mtime", "findings", "snippets"])
        for r in results:
            w.writerow([
                r["risk"],
                r["score"],
                r["path"],
                r["full_path"],
                r["size"],
                r["entropy"],
                r["mtime"],
                " | ".join(_strip_ansi(x) for x in (r.get("findings") or [])),
                " | ".join(r.get("snippets") or []),
            ])
    print("%s[*] CSV report written: %s%s" % (C_GREEN, out_path, C_RESET))


def quarantine_files(results, quarantine_dir, min_risk="HIGH"):
    """
    Move HIGH/CRITICAL (or all reported) files into quarantine_dir,
    preserving a relative path structure. Returns count moved.
    """
    order = {"MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    min_level = order.get(min_risk.upper(), 2)
    qroot = Path(quarantine_dir)
    qroot.mkdir(parents=True, exist_ok=True)
    moved = 0
    for r in results:
        if order.get(r["risk"], 0) < min_level:
            continue
        src = Path(r["full_path"])
        if not src.is_file():
            continue
        # Preserve relative structure under quarantine
        dest = qroot / r["path"]
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            # Avoid overwrite collisions
            if dest.exists():
                dest = dest.with_name(dest.name + "." + str(int(time.time())))
            src.rename(dest)
            # Leave a note at original location
            note = src.with_suffix(src.suffix + ".quarantined.txt")
            try:
                note.write_text(
                    "Quarantined by wpbdscanner on %s\nOriginal: %s\nMoved to: %s\nRisk: %s Score: %d\n"
                    % (datetime.now().isoformat(), r["full_path"], dest, r["risk"], r["score"]),
                    encoding="utf-8",
                )
            except Exception:
                pass
            moved += 1
            print("%s  [Q] %s → %s%s" % (C_YELLOW, r["path"], dest, C_RESET))
        except Exception as e:
            print("%s  [!] Failed to quarantine %s: %s%s" % (C_RED, r["path"], e, C_RESET))
    return moved


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_banner():
    print("""
%s╔══════════════════════════════════════════════════════════════╗
║          WP Backdoor / Malware Deep Scanner v1.3             ║
║  WordPress shells • checksum verify • reduced false positives║
╚══════════════════════════════════════════════════════════════╝%s
""" % (C_CYAN, C_RESET))


def print_results(results, root, elapsed):
    if not results:
        print("\n%s[✓] No high-confidence backdoors or malware detected.%s" % (C_GREEN, C_RESET))
        print("%s    (Official plugin files, protection stubs & low-score heuristics filtered)%s\n" % (C_DIM, C_RESET))
        print("%s[*] Elapsed: %s%s\n" % (C_CYAN, format_elapsed(elapsed), C_RESET))
        return

    print("\n%s%s" % (C_RED, "=" * 64))
    print("  FOUND %d SUSPICIOUS FILE(S)" % len(results))
    print("%s%s\n" % ("=" * 64, C_RESET))

    for r in results:
        print("%s %s %s  Score: %s%d%s" % (r["risk_color"], r["risk"], C_RESET, C_WHITE, r["score"], C_RESET))
        print("  %sFile:%s     %s" % (C_CYAN, C_RESET, r["path"]))
        print("  %sFull:%s     %s" % (C_DIM, C_RESET, r["full_path"]))
        print("  %sSize:%s     %d bytes  |  Entropy: %s  |  MTime: %s" % (
            C_DIM, C_RESET, r["size"], r["entropy"], r["mtime"]))
        print("  %sIndicators:%s" % (C_YELLOW, C_RESET))
        for f in r["findings"]:
            print("      • %s" % f)
        snips = r.get("snippets") or []
        if snips:
            print("  %sMatched lines:%s" % (C_MAGENTA, C_RESET))
            for s in snips:
                print("      %s%s%s" % (C_DIM, s, C_RESET))
        print()

    print("%s[!] Review HIGH/CRITICAL items carefully. Prefer quarantining over deleting.%s" % (C_YELLOW, C_RESET))
    print("%s    Files marked [VERIFIED] matched wordpress.org and were suppressed when safe.%s" % (C_DIM, C_RESET))
    print("%s    Files marked [MODIFIED] differ from the official package — investigate.%s\n" % (C_DIM, C_RESET))
    print("%s[*] Elapsed: %s%s\n" % (C_CYAN, format_elapsed(elapsed), C_RESET))


# Runtime config set from CLI (used by collect_files / analyze_file)
IGNORE_PATTERNS = []
YARA_RULES_PATH = None
_ANALYZING_PATHS = set()
_ANALYZING_LOCK = threading.Lock()
_DISCOVERED_RESULTS = []
_DISCOVERED_LOCK = threading.Lock()


def main():
    global IGNORE_PATTERNS, YARA_RULES_PATH

    parser = argparse.ArgumentParser(
        description="Deep scanner for WordPress backdoors, PHP shells and malware.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wpbdscanner.py --dir /home/user/public_html/wp-content/
  python wpbdscanner.py --dir /var/www/html --threads 8
  python wpbdscanner.py -d ./wp-content -t 4 --json report.json
  python wpbdscanner.py -d ./wp-content --csv report.csv --quarantine /tmp/wp-quarantine
  python wpbdscanner.py -d ./wp-content --ignore ignore.txt
  python wpbdscanner.py -d ./wp-content --yara rules/webshells.yar

Notes:
  - Plugin files under wp-content/plugins/ are checked against
    official WordPress.org SHA-256 checksums when possible.
  - Matching official files are suppressed (not reported).
  - Modified or extra files are elevated in severity.
  - Pair with: wp core verify-checksums && wp plugin verify-checksums --all
        """,
    )
    parser.add_argument("--dir", "-d", required=True,
                        help="Directory to scan (e.g. /home/user/public_html/wp-content/)")
    parser.add_argument("--threads", "-t", type=int, default=4,
                        help="Number of worker threads (default: 4)")
    parser.add_argument("--json", metavar="FILE",
                        help="Write machine-readable JSON report to FILE")
    parser.add_argument("--csv", metavar="FILE",
                        help="Write CSV report to FILE")
    parser.add_argument("--quarantine", metavar="DIR",
                        help="Move HIGH/CRITICAL files into DIR (preserves relative paths)")
    parser.add_argument("--quarantine-level", default="HIGH",
                        choices=["MEDIUM", "HIGH", "CRITICAL"],
                        help="Minimum risk to quarantine (default: HIGH)")
    parser.add_argument("--ignore", metavar="FILE",
                        help="Ignore patterns file (substring or *.ext per line)")
    parser.add_argument("--yara", metavar="FILE",
                        help="Optional YARA rules file (requires yara-python)")
    args = parser.parse_args()

    root = Path(args.dir).resolve()
    if not root.is_dir():
        print("%s[!] Directory does not exist or is not accessible: %s%s" % (C_RED, root, C_RESET))
        sys.exit(1)

    threads = max(1, min(args.threads, 32))
    IGNORE_PATTERNS = load_ignore_patterns(args.ignore) if args.ignore else []
    YARA_RULES_PATH = args.yara

    if args.yara:
        try:
            import yara  # noqa: F401
        except ImportError:
            print("%s[!] --yara set but yara-python is not installed. Install: pip install yara-python%s"
                  % (C_YELLOW, C_RESET))
            print("%s    Continuing without YARA.%s\n" % (C_DIM, C_RESET))
            YARA_RULES_PATH = None

    print_banner()
    print("%s[*] Target : %s%s%s" % (C_CYAN, C_WHITE, root, C_RESET))
    print("%s[*] Threads: %s%d%s" % (C_CYAN, C_WHITE, threads, C_RESET))
    if IGNORE_PATTERNS:
        print("%s[*] Ignore : %s%d pattern(s) from %s%s" % (C_CYAN, C_WHITE, len(IGNORE_PATTERNS), args.ignore, C_RESET))
    if YARA_RULES_PATH:
        print("%s[*] YARA   : %s%s%s" % (C_CYAN, C_WHITE, YARA_RULES_PATH, C_RESET))
    print("%s[*] Started: %s%s%s\n" % (
        C_CYAN, C_WHITE, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), C_RESET))

    try:
        results, elapsed = scan(root, threads)
        # Apply ignore filter on results (also filtered at collect time)
        if IGNORE_PATTERNS:
            results = [r for r in results if not path_is_ignored(r["full_path"], IGNORE_PATTERNS)]
        print_results(results, root, elapsed)

        if args.json:
            export_json(results, root, elapsed, args.json)
        if args.csv:
            export_csv(results, args.csv)
        if args.quarantine and results:
            print("%s[*] Quarantining ≥%s into %s ...%s" % (C_CYAN, args.quarantine_level, args.quarantine, C_RESET))
            n = quarantine_files(results, args.quarantine, args.quarantine_level)
            print("%s[*] Quarantined %d file(s).%s\n" % (C_GREEN, n, C_RESET))
    except KeyboardInterrupt:
        print("\n%s[!] Scan interrupted by user.%s" % (C_YELLOW, C_RESET))
        sys.exit(130)
    except Exception as e:
        print("%s[!] Unexpected error: %s%s" % (C_RED, e, C_RESET))
        sys.exit(1)

    print("%s[*] Scan finished.%s" % (C_GREEN, C_RESET))


if __name__ == "__main__":
    main()
