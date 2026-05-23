"""Per-check WAF rule snippet generator.

For findings that can be mitigated at the edge (Cloudflare, AWS WAF,
ModSecurity / Nginx), generate a copy-pasteable rule snippet that blocks
the attack vector. Surfaced in the HTML report and the GUI detail pane.

Defensive — these rules BLOCK traffic, they don't probe anything.
"""
from __future__ import annotations

# (check_id) -> {cloudflare, modsecurity, nginx} rule fragments
# Each value is a copy-pasteable snippet. Comments inline explain context.
RULES: dict[str, dict] = {
    "exposed_files": {
        "title": "Block requests for backup / config file extensions",
        "cloudflare": (
            '(http.request.uri.path matches "\\\\.(bak|swp|sql|env|gitconfig|gitignore|old)$")\n'
            "or (http.request.uri.path eq \"/.git/config\")\n"
            "or (http.request.uri.path eq \"/wp-config.php.bak\")"
        ),
        "modsecurity": (
            'SecRule REQUEST_URI "@rx \\\\.(bak|swp|sql|env|gitconfig|old)$" \\\n'
            '  "id:9000,phase:1,deny,status:404,log,msg:\'Block exposed file\'"'
        ),
        "nginx": (
            "location ~* \\.(bak|swp|sql|env|gitconfig|old)$ { deny all; }\n"
            "location ~ /\\.git { deny all; }\n"
            "location = /wp-config.php { deny all; }"
        ),
    },
    "xmlrpc_deep": {
        "title": "Block / restrict /xmlrpc.php",
        "cloudflare": (
            "(http.request.uri.path eq \"/xmlrpc.php\")\n"
            "# Action: BLOCK  (or Challenge if you have legitimate XML-RPC clients)"
        ),
        "modsecurity": (
            'SecRule REQUEST_URI "@streq /xmlrpc.php" \\\n'
            '  "id:9010,phase:1,deny,status:403,log,msg:\'Block xmlrpc.php\'"'
        ),
        "nginx": "location = /xmlrpc.php { deny all; }",
    },
    "login_throttle": {
        "title": "Rate-limit /wp-login.php at the edge",
        "cloudflare": (
            "# Cloudflare → Security → Rate limiting:\n"
            "# Path equals /wp-login.php, requests > 5 in 1 minute → Block 10 min"
        ),
        "modsecurity": (
            'SecRule REQUEST_URI "@streq /wp-login.php" \\\n'
            '  "id:9020,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR},setvar:\'ip.login_attempts=+1\',expirevar:ip.login_attempts=60"\n'
            'SecRule IP:LOGIN_ATTEMPTS "@gt 5" \\\n'
            '  "id:9021,phase:1,deny,status:429,log,msg:\'wp-login.php brute-force\'"'
        ),
        "nginx": (
            "limit_req_zone $binary_remote_addr zone=wplogin:10m rate=5r/m;\n"
            "location = /wp-login.php { limit_req zone=wplogin burst=2 nodelay; }"
        ),
    },
    "tls_headers": {
        "title": "Add missing security headers at the edge",
        "cloudflare": (
            "# Cloudflare → Rules → Transform Rules → Modify Response Header:\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "X-Content-Type-Options: nosniff\n"
            "X-Frame-Options: SAMEORIGIN\n"
            "Referrer-Policy: strict-origin-when-cross-origin\n"
            "Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
        "modsecurity": (
            'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"\n'
            'Header always set X-Content-Type-Options "nosniff"\n'
            'Header always set X-Frame-Options "SAMEORIGIN"\n'
            'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
        ),
        "nginx": (
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n'
            "add_header X-Content-Type-Options nosniff always;\n"
            "add_header X-Frame-Options SAMEORIGIN always;\n"
            "add_header Referrer-Policy strict-origin-when-cross-origin always;"
        ),
    },
    "directory_listing": {
        "title": "Disable directory listing",
        "cloudflare": "# Cloudflare can't disable autoindex on origin — fix at origin instead.",
        "modsecurity": "Options -Indexes",
        "nginx": "autoindex off;  # default; ensure no `autoindex on;` in any location block",
    },
    "users": {
        "title": "Block /?author= author enumeration + /wp-json/wp/v2/users",
        "cloudflare": (
            "(http.request.uri contains \"author=\" and http.request.uri.path eq \"/\")\n"
            "or (http.request.uri.path eq \"/wp-json/wp/v2/users\")\n"
            "# Action: Block (or Challenge)"
        ),
        "modsecurity": (
            'SecRule ARGS:author "@rx ^\\d+$" \\\n'
            '  "id:9030,phase:1,deny,status:404,log,msg:\'Block ?author=N enumeration\'"\n'
            'SecRule REQUEST_URI "@streq /wp-json/wp/v2/users" \\\n'
            '  "id:9031,phase:1,deny,status:404,log,msg:\'Block REST user enum\'"'
        ),
        "nginx": (
            'if ($arg_author ~ "^\\d+$") { return 404; }\n'
            "location = /wp-json/wp/v2/users { deny all; }"
        ),
    },
    "http_methods": {
        "title": "Restrict allowed HTTP methods",
        "cloudflare": "(http.request.method in {\"TRACE\" \"TRACK\" \"PATCH\" \"PUT\" \"DELETE\"})\n# Action: Block",
        "modsecurity": (
            'SecRule REQUEST_METHOD "!@within GET HEAD POST OPTIONS" \\\n'
            '  "id:9040,phase:1,deny,status:405,log,msg:\'Method not allowed\'"'
        ),
        "nginx": "if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) { return 405; }",
    },
    "cors": {
        "title": "Lock down Access-Control-Allow-Origin",
        "cloudflare": "# Cloudflare Transform Rules → Modify Response Header → Access-Control-Allow-Origin: https://yourdomain.tld",
        "modsecurity": "# Remove any Header set Access-Control-Allow-Origin '*' directives.",
        "nginx": "add_header Access-Control-Allow-Origin \"https://yourdomain.tld\" always;",
    },
    "wpgraphql": {
        "title": "Restrict /graphql to authenticated users",
        "cloudflare": (
            "(http.request.uri.path in {\"/graphql\" \"/wp-json/wp/v2/graphql\"}\n"
            " and not http.cookie contains \"wordpress_logged_in\")\n"
            "# Action: Block"
        ),
        "modsecurity": "# Combine with a request-rate rule — GraphQL endpoints are amplifiers.",
        "nginx": "location = /graphql { allow <office-ip>; deny all; }",
    },
    "default_creds": {
        "title": "Block known default username at the edge",
        "cloudflare": (
            "(http.request.uri.path eq \"/wp-login.php\" and\n"
            " any(http.request.body.form[\"log\"][*] in {\"admin\" \"administrator\" \"wp-admin\" \"root\"}))\n"
            "# Action: Block + alert"
        ),
        "modsecurity": (
            'SecRule ARGS_POST:log "@within admin administrator root wp-admin" \\\n'
            '  "id:9050,phase:2,deny,status:403,log,msg:\'Block default username login\'"'
        ),
        "nginx": "# Best done at WP layer via Limit Login Attempts plugin.",
    },
}


def get_rule(check_id: str) -> dict | None:
    """Return the rule dict for a check, or None if no rule mapped."""
    return RULES.get(check_id)
