/**
 * Post-build link and asset check against the static output.
 *
 * Catches the two failure modes that only appear after deployment: a link
 * missing the deployment base prefix, and a reference to an asset or page
 * that the build did not emit. Run `npm run build && npm run check:links`.
 *
 * Cloudflare Pages serves the project at the domain root, so `BASE` is `/`;
 * set `SITE_BASE` to audit a sub-path deployment instead.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const DIST = path.resolve("dist");
const RAW_BASE = process.env.SITE_BASE ?? "/";
const BASE = RAW_BASE.endsWith("/") ? RAW_BASE : `${RAW_BASE}/`;
const EXPECTED_HREFLANG = 6; // en, zh, es, fr, ja + x-default

if (!existsSync(DIST)) {
  console.error("✖ dist/ not found — run `npm run build` first.");
  process.exit(1);
}

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (name.endsWith(".html")) out.push(full);
  }
  return out;
}

const pages = walk(DIST);
const errors = [];
const missingAssets = new Set();
let checked = 0;

function resolveTarget(rawUrl) {
  const withoutHash = rawUrl.split("#")[0].split("?")[0];
  if (!withoutHash) return null;
  let rel = decodeURIComponent(withoutHash.slice(BASE.length));
  if (rel === "") rel = "index.html";
  const direct = path.join(DIST, rel);
  if (existsSync(direct) && statSync(direct).isFile()) return direct;
  if (!path.extname(rel)) {
    const indexFile = path.join(DIST, rel, "index.html");
    if (existsSync(indexFile)) return indexFile;
    const htmlFile = path.join(DIST, `${rel}.html`);
    if (existsSync(htmlFile)) return htmlFile;
  }
  return null;
}

for (const page of pages) {
  const html = readFileSync(page, "utf8");
  const relative = path.relative(DIST, page);
  // Non-indexable pages (404) intentionally omit canonical and hreflang links.
  const noindex = /<meta[^>]+name="robots"[^>]+noindex/.test(html);
  if (!noindex) {
    const hreflangs = [...html.matchAll(/<link[^>]+hreflang="[^"]+"[^>]*>/g)];
    if (hreflangs.length !== EXPECTED_HREFLANG) {
      errors.push(
        `${relative} — expected ${EXPECTED_HREFLANG} hreflang links, found ${hreflangs.length}`,
      );
    }
  }

  const refs = [
    ...html.matchAll(/(?:href|src)="([^"]+)"/g),
    ...html.matchAll(/srcset="([^"]+)"/g).flatMap((match) =>
      match[1].split(",").map((candidate) => [null, candidate.trim().split(/\s+/)[0]]),
    ),
  ];

  for (const match of refs) {
    const value = match[1];
    if (!value) continue;
    if (/^(?:[a-z]+:|\/\/|#)/i.test(value) && !value.startsWith(BASE)) continue;
    if (!value.startsWith(BASE)) {
      if (value.startsWith("/")) {
        errors.push(`${relative} — link "${value}" ignores the ${BASE} base path`);
      }
      continue;
    }
    checked += 1;
    const resolved = resolveTarget(value);
    if (!resolved) {
      const clean = value.split("#")[0].split("?")[0];
      if (/\.[a-z0-9]{2,5}$/i.test(clean)) missingAssets.add(clean);
      else errors.push(`${relative} — broken link "${value}"`);
    }
  }
}

if (missingAssets.size) {
  for (const asset of missingAssets) errors.push(`missing asset ${asset}`);
}

if (errors.length) {
  console.error(`\n✖ ${errors.length} link error(s) across ${pages.length} page(s):`);
  for (const error of errors.slice(0, 80)) console.error(`  - ${error}`);
  if (errors.length > 80) console.error(`  … ${errors.length - 80} more`);
  process.exit(1);
}

console.log(`✔ links OK — ${checked} internal references across ${pages.length} page(s)`);
