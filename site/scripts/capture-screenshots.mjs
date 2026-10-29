#!/usr/bin/env node
/**
 * Capture the console screenshots used across the portal.
 *
 * The dashboard is a real React SPA (`web/dist`) that talks to `/api/v1`. No
 * control plane is required: this script serves the built bundle locally and
 * fulfils every API call from `scripts/fixtures.mjs`, then screenshots the
 * pages at 1440×900 with a 2× device pixel ratio.
 *
 *   npm run capture                 # mock mode (default)
 *   npm run capture -- --live \
 *     --base=https://localhost:9080 # real control plane
 *
 * Live mode needs `E2E_ADMIN_EMAIL` and `E2E_ADMIN_PASSWORD` in the
 * environment and performs a real login instead of injecting a session.
 */
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { routes } from "./fixtures.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const siteRoot = path.resolve(here, "..");
const repoRoot = path.resolve(siteRoot, "..");
const distDir = path.join(repoRoot, "web", "dist");
const outDir = path.join(siteRoot, "src", "assets", "screenshots");

const args = new Map(
  process.argv.slice(2).map((arg) => {
    const [key, value = "true"] = arg.replace(/^--/, "").split("=");
    return [key, value];
  }),
);
const live = args.has("live");
const baseUrl = args.get("base") ?? "";
const port = Number(args.get("port") ?? 4174);
const siteId = "site_demo0001";

const VIEWPORT = { width: 1440, height: 900 };

const SHOTS = [
  { key: "dashboard", path: "/dashboard" },
  { key: "sites", path: "/sites" },
  { key: "login", path: "/login", anonymous: true },
  { key: "waf", path: `/sites/${siteId}/security/protection` },
  { key: "cc", path: `/sites/${siteId}/security/rate-limiting` },
  { key: "bot", path: `/sites/${siteId}/security/bot` },
  { key: "access", path: `/sites/${siteId}/security/access` },
  { key: "caching", path: `/sites/${siteId}/caching` },
  { key: "ssl", path: `/sites/${siteId}/ssl` },
  { key: "logs", path: "/logs" },
  { key: "agents", path: "/agents" },
  { key: "configVersions", path: "/config-versions", scroll: 1180 },
];

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".json": "application/json",
  ".map": "application/json",
};

function loadPlaywright() {
  const candidates = [
    path.join(repoRoot, "e2e", "package.json"),
    path.join(repoRoot, "web", "package.json"),
    path.join(siteRoot, "package.json"),
  ];
  for (const candidate of candidates) {
    try {
      const require = createRequire(candidate);
      return require("@playwright/test");
    } catch (error) {
      // try the next resolution root
    }
  }
  throw new Error(
    "Playwright not found. Install it (npm i -D @playwright/test) or reuse e2e/node_modules.",
  );
}

/** Serve `web/dist` with the same fallback rules as the Rust frontend host. */
function startStaticServer(rootDir) {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const decoded = decodeURIComponent(url.pathname);
    const relative = decoded.replace(/^\/+/, "");
    const target = path.join(rootDir, relative);

    const sendFile = (file) => {
      res.writeHead(200, { "content-type": MIME[path.extname(file)] ?? "application/octet-stream" });
      res.end(readFileSync(file));
    };

    if (relative && existsSync(target) && statSync(target).isFile()) {
      sendFile(target);
      return;
    }

    const looksLikeAsset = relative.startsWith("assets/") || /\.[a-z0-9]{2,5}$/i.test(relative);
    if (looksLikeAsset) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "not_found", message: "asset missing" } }));
      return;
    }

    sendFile(path.join(rootDir, "index.html"));
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

async function waitForRender(page) {
  try {
    await page.waitForFunction(
      () => document.querySelectorAll(".pw-skeleton").length === 0,
      undefined,
      { timeout: 15000 },
    );
  } catch (error) {
    // Pages without skeletons are fine; keep going.
  }
  await page.waitForTimeout(700);
}

/**
 * Reuse any Chromium already present in the Playwright cache. The e2e suite
 * pins a slightly different revision than the one this script resolves, and a
 * cached build is good enough for screenshots.
 */
function findCachedChromium() {
  const cacheRoot = path.join(
    process.env.HOME ?? "",
    "Library",
    "Caches",
    "ms-playwright",
  );
  if (!existsSync(cacheRoot)) return undefined;
  const candidates = [];
  for (const entry of readdirSync(cacheRoot)) {
    if (entry.startsWith("chromium_headless_shell-")) {
      candidates.push(
        path.join(cacheRoot, entry, "chrome-headless-shell-mac-arm64", "chrome-headless-shell"),
        path.join(cacheRoot, entry, "chrome-headless-shell-linux64", "chrome-headless-shell"),
      );
    } else if (entry.startsWith("chromium-")) {
      candidates.push(
        path.join(
          cacheRoot,
          entry,
          "chrome-mac-arm64",
          "Google Chrome for Testing.app",
          "Contents",
          "MacOS",
          "Google Chrome for Testing",
        ),
        path.join(cacheRoot, entry, "chrome-linux64", "chrome"),
      );
    }
  }
  return candidates.find((candidate) => existsSync(candidate));
}

async function main() {
  if (!existsSync(path.join(distDir, "index.html"))) {
    throw new Error(
      `web/dist not found (${distDir}). Run \`make build-web\` or \`cd web && npm run build\` first.`,
    );
  }

  mkdirSync(outDir, { recursive: true });
  const { chromium } = loadPlaywright();

  const server = live || baseUrl ? null : await startStaticServer(distDir);
  const origin = baseUrl || `http://127.0.0.1:${port}`;

  const executablePath = findCachedChromium();
  const browser = await chromium.launch({ headless: true, executablePath });
  const context = await browser.newContext({
    viewport: VIEWPORT,
    deviceScaleFactor: 2,
    colorScheme: "light",
    reducedMotion: "reduce",
    locale: "en-US",
    ignoreHTTPSErrors: true,
  });

  const session = {
    token: "demo.session.token",
    refreshToken: "demo.refresh.token",
    user: {
      id: "usr_demo0001",
      email: "admin@example.com",
      name: "Demo Admin",
      role: "admin",
      must_change_password: false,
      disabled: false,
      created_at: "2025-01-06T08:00:00Z",
      updated_at: "2026-02-11T09:30:00Z",
    },
  };

  await context.addInitScript((payload) => {
    try {
      localStorage.setItem("pingwaf.lang", "en");
      localStorage.setItem("pingwaf.theme", "light");
      localStorage.setItem("pingwaf.token", payload.token);
      localStorage.setItem("pingwaf.refreshToken", payload.refreshToken);
      localStorage.setItem("pingwaf.user", JSON.stringify(payload.user));
    } catch (error) {
      /* storage unavailable */
    }
  }, session);

  // The login screen redirects authenticated sessions, so it gets a clean
  // context with no injected token or user.
  const anonContext = await browser.newContext({
    viewport: VIEWPORT,
    deviceScaleFactor: 2,
    colorScheme: "light",
    reducedMotion: "reduce",
    locale: "en-US",
    ignoreHTTPSErrors: true,
  });
  await anonContext.addInitScript(() => {
    try {
      localStorage.setItem("pingwaf.lang", "en");
      localStorage.setItem("pingwaf.theme", "light");
    } catch (error) {
      /* storage unavailable */
    }
  });

  const page = await context.newPage();
  const anonPage = await anonContext.newPage();
  page.setDefaultTimeout(20000);
  anonPage.setDefaultTimeout(20000);

  if (!live) {
    const fulfil = async (route) => {
      const url = new URL(route.request().url());
      const body = routes(url.pathname);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(body ?? {}),
      });
    };
    await context.route("**/api/v1/**", fulfil);
    await anonContext.route("**/api/v1/**", fulfil);
  } else {
    const email = process.env.E2E_ADMIN_EMAIL;
    const password = process.env.E2E_ADMIN_PASSWORD;
    if (!email || !password) {
      throw new Error("Live mode needs E2E_ADMIN_EMAIL and E2E_ADMIN_PASSWORD.");
    }
    await page.goto(`${origin}/login`, { waitUntil: "domcontentloaded" });
    await page.fill('form input[type="email"]', email);
    await page.fill('form input[type="password"]', password);
    await page.click('form button[type="submit"]');
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 20000 });
  }

  const results = [];
  for (const shot of SHOTS) {
    const active = shot.anonymous ? anonPage : page;
    const target = new URL(shot.path, `${origin}/`).toString();
    await active.goto(target, { waitUntil: "domcontentloaded" });
    await waitForRender(active);
    await active.addStyleTag({
      content:
        "*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important}::-webkit-scrollbar{display:none!important}",
    });
    if (shot.scroll) {
      await active.evaluate((offset) => {
        window.scrollTo({ top: offset, behavior: "instant" });
        if (window.scrollY >= offset - 4) return;
        // The console scrolls inside its main region, not the document.
        const scroller = Array.from(document.querySelectorAll("main, [class]")).find((element) => {
          const style = getComputedStyle(element);
          const scrollable = /(auto|scroll)/.test(style.overflowY);
          return scrollable && element.scrollHeight - element.clientHeight > 400;
        });
        scroller?.scrollTo({ top: offset, behavior: "instant" });
      }, shot.scroll);
      await active.waitForTimeout(500);
    }
    // A missing fixture surfaces as the console's error boundary, which would
    // otherwise be committed as a "screenshot". Fail loudly instead.
    const errorPage = await active.evaluate(() => {
      const text = document.body ? document.body.innerText : "";
      if (!text.includes("Unexpected Application Error")) return "";
      return text.split("\n").filter(Boolean).slice(0, 2).join(" — ");
    });
    if (errorPage) {
      const debugDir = path.join(siteRoot, ".capture-tmp");
      mkdirSync(debugDir, { recursive: true });
      await active.screenshot({ path: path.join(debugDir, `${shot.key}.failed.png`) });
      throw new Error(
        `${shot.key} (${shot.path}) rendered the console error page: ${errorPage}`,
      );
    }

    const file = path.join(outDir, `${shot.key}.png`);
    await active.screenshot({ path: file, animations: "disabled", caret: "hide" });
    results.push({ key: shot.key, path: shot.path, file: path.relative(siteRoot, file) });
    console.log(`✔ ${shot.key.padEnd(15)} ${shot.path}`);
  }

  await browser.close();
  if (server) server.close();

  console.log(`\n${results.length} screenshot(s) → ${path.relative(process.cwd(), outDir)}`);
  console.log(`mode: ${live ? "live" : "mock"} · viewport: ${VIEWPORT.width}×${VIEWPORT.height} @2x`);
}

main().catch((error) => {
  console.error(`\n✖ capture failed: ${error.message}`);
  process.exit(1);
});
