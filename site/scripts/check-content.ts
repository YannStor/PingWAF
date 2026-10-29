/**
 * Build-time content contract check.
 *
 * Verifies that all five locales implement the same content shape, that every
 * referenced screenshot/link/document exists, and that no placeholder copy is
 * left behind. Run with `npm run check:content`.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { DOC_SLUGS, ROUTES, SCREENSHOT_KEYS, docPath } from "../src/content/schema.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const contentDir = path.join(root, "src", "content");
const docsDir = path.join(contentDir, "docs");

const LOCALES = ["en", "zh", "es", "fr", "ja"] as const;
const MODULES = ["intro", "features", "quickstart", "docs"] as const;

const errors: string[] = [];
const warnings: string[] = [];
let checks = 0;

const fail = (message: string) => errors.push(message);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describePath(segments: string[]): string {
  return segments.length ? segments.join(".") : "<root>";
}

/** Compare the shape of a translation against the English source of truth. */
function compareShape(
  reference: unknown,
  candidate: unknown,
  segments: string[],
  locale: string,
): void {
  checks += 1;
  const where = `${locale}:${describePath(segments)}`;

  if (Array.isArray(reference)) {
    if (!Array.isArray(candidate)) {
      fail(`${where} — expected an array, got ${typeof candidate}`);
      return;
    }
    if (candidate.length !== reference.length) {
      fail(`${where} — expected ${reference.length} entries, got ${candidate.length}`);
    }
    const count = Math.min(reference.length, candidate.length);
    for (let i = 0; i < count; i += 1) {
      compareShape(reference[i], candidate[i], [...segments, String(i)], locale);
    }
    return;
  }

  if (isPlainObject(reference)) {
    if (!isPlainObject(candidate)) {
      fail(`${where} — expected an object, got ${typeof candidate}`);
      return;
    }
    const referenceKeys = Object.keys(reference).sort();
    const candidateKeys = Object.keys(candidate).sort();
    for (const key of referenceKeys) {
      if (!(key in candidate)) {
        fail(`${where} — missing key "${key}"`);
      }
    }
    for (const key of candidateKeys) {
      if (!(key in reference)) {
        fail(`${where} — unexpected key "${key}"`);
      }
    }
    for (const key of referenceKeys) {
      if (key in candidate) {
        compareShape(reference[key], candidate[key], [...segments, key], locale);
      }
    }
    return;
  }

  if (typeof reference === "string") {
    if (typeof candidate !== "string") {
      fail(`${where} — expected a string`);
      return;
    }
    if (candidate.trim().length === 0) {
      fail(`${where} — empty string`);
    }
    if (/\b(TODO|FIXME):|\blorem ipsum\b/i.test(candidate)) {
      fail(`${where} — placeholder copy left in translation`);
    }
    // Machine identifiers legitimately stay identical across locales.
    const technical = /(\.(code|lang|id|key|url|path|slug|icon|verdict)$|\.topics\.\d+$)/;
    if (candidate === reference && locale !== "en" && !technical.test(where)) {
      warnings.push(`${where} — identical to English (check the translation)`);
    }
    return;
  }

  if (typeof reference === "number" && typeof candidate !== "number") {
    fail(`${where} — expected a number`);
  }
}

interface LinkLike {
  label: string;
  path: string;
}

const knownPaths = new Set<string>([
  ROUTES.home,
  ROUTES.features,
  ROUTES.quickstart,
  ROUTES.docs,
  ...DOC_SLUGS.map((slug) => docPath(slug)),
]);

function checkLink(locale: string, where: string, link: LinkLike): void {
  if (!link || typeof link.path !== "string") {
    fail(`${locale}:${where} — link is missing a path`);
    return;
  }
  const { path: target } = link;
  if (/^https?:\/\//.test(target)) return;
  const [base, hash] = target.split("#");
  const normalized = base === "" ? "" : base.endsWith("/") ? base : `${base}/`;
  if (!knownPaths.has(normalized) && !knownPaths.has(base)) {
    fail(`${locale}:${where} — unknown internal link "${target}"`);
    return;
  }
  if (hash && normalized === ROUTES.features) {
    checks += 1;
  }
}

function checkShot(locale: string, where: string, shot: { key?: string } | undefined): void {
  if (!shot || typeof shot.key !== "string") {
    fail(`${locale}:${where} — screenshot key missing`);
    return;
  }
  if (!(SCREENSHOT_KEYS as readonly string[]).includes(shot.key)) {
    fail(`${locale}:${where} — unknown screenshot key "${shot.key}"`);
  }
}

function checkUnique(locale: string, where: string, ids: string[]): void {
  const seen = new Set<string>();
  for (const id of ids) {
    if (seen.has(id)) fail(`${locale}:${where} — duplicate id "${id}"`);
    seen.add(id);
  }
}

async function loadModule(locale: string, module: string): Promise<Record<string, unknown> | null> {
  const file = path.join(contentDir, locale, `${module}.ts`);
  if (!existsSync(file)) return null;
  const imported = (await import(pathToFileURL(file).href)) as { default?: Record<string, unknown> };
  return imported.default ?? null;
}

function parseFrontmatter(source: string): Record<string, string> {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(source);
  if (!match) return {};
  const data: Record<string, string> = {};
  for (const line of match[1].split(/\r?\n/)) {
    const pair = /^([A-Za-z_][\w-]*):\s*(.*)$/.exec(line);
    if (pair) data[pair[1]] = pair[2].replace(/^["']|["']$/g, "").trim();
  }
  return data;
}

const english: Record<string, Record<string, unknown>> = {};

for (const module of MODULES) {
  const loaded = await loadModule("en", module);
  if (!loaded) {
    fail(`en:${module} — missing (src/content/en/${module}.ts is the source of truth)`);
    continue;
  }
  english[module] = loaded;
}

for (const locale of LOCALES) {
  for (const module of MODULES) {
    const reference = english[module];
    if (!reference) continue;

    if (locale === "en") continue;

    const candidate = await loadModule(locale, module);
    if (!candidate) {
      fail(`${locale}:${module} — missing translation (src/content/${locale}/${module}.ts)`);
      continue;
    }
    compareShape(reference, candidate, [], `${locale}/${module}`);
  }
}

/* ------------------------------------------------------------ module rules */

const featuresEn = english.features as
  | { hero: { toc: Array<{ id: string }> }; groups: Array<{ id: string; points: string[]; shot: unknown }> }
  | undefined;

for (const locale of LOCALES) {
  const features = (await loadModule(locale, "features")) as typeof featuresEn | null;
  if (!features) continue;

  const ids = features.groups.map((group) => group.id);
  checkUnique(locale, "features.groups", ids);

  if (features.hero.toc.length !== ids.length) {
    fail(`${locale}:features.hero.toc — ${features.hero.toc.length} entries for ${ids.length} groups`);
  }
  for (const entry of features.hero.toc) {
    if (!ids.includes(entry.id)) {
      fail(`${locale}:features.hero.toc — "${entry.id}" does not match any group id`);
    }
  }
  for (const group of features.groups) {
    checkShot(locale, `features.groups.${group.id}`, group.shot as { key?: string });
    if (group.points.length < 3) {
      warnings.push(`${locale}:features.groups.${group.id} — fewer than 3 points`);
    }
  }

  const intro = (await loadModule(locale, "intro")) as
    | { capabilities: { items: Array<{ link?: LinkLike }> }; hero: { shot: unknown }; showcase: { shots: unknown[] }; architecture: { link: LinkLike } }
    | null;
  if (intro) {
    checkShot(locale, "intro.hero.shot", intro.hero.shot as { key?: string });
    intro.showcase.shots.forEach((shot, index) =>
      checkShot(locale, `intro.showcase.shots.${index}`, shot as { key?: string }),
    );
    checkLink(locale, "intro.architecture.link", intro.architecture.link);
    intro.capabilities.items.forEach((item, index) => {
      if (item.link) {
        checkLink(locale, `intro.capabilities.items.${index}.link`, item.link);
        const anchor = item.link.path.split("#")[1];
        if (anchor && !ids.includes(anchor)) {
          fail(`${locale}:intro.capabilities.items.${index}.link — unknown feature anchor "#${anchor}"`);
        }
      }
    });
  }

  const quickstart = (await loadModule(locale, "quickstart")) as
    | {
        hero: { toc: Array<{ id: string }> };
        paths: { docker: { id: string }; source: { id: string } };
        credentials: { shot: unknown };
        next: { cards: Array<{ link: LinkLike }> };
      }
    | null;
  if (quickstart) {
    const tocIds = quickstart.hero.toc.map((entry) => entry.id);
    for (const id of [quickstart.paths.docker.id, quickstart.paths.source.id]) {
      if (!tocIds.includes(id)) {
        fail(`${locale}:quickstart.hero.toc — missing path section "${id}"`);
      }
    }
    checkShot(locale, "quickstart.credentials.shot", quickstart.credentials.shot as { key?: string });
    quickstart.next.cards.forEach((card, index) =>
      checkLink(locale, `quickstart.next.cards.${index}.link`, card.link),
    );
  }

  const docsContent = (await loadModule(locale, "docs")) as
    | { cards: Array<{ slug: string }>; screenshot: unknown; github: { link: LinkLike } }
    | null;
  if (docsContent) {
    const slugs = docsContent.cards.map((card) => card.slug);
    for (const slug of DOC_SLUGS) {
      if (!slugs.includes(slug)) fail(`${locale}:docs.cards — missing "${slug}"`);
    }
    checkShot(locale, "docs.screenshot", docsContent.screenshot as { key?: string });
    checkLink(locale, "docs.github.link", docsContent.github.link);
  }
}

/* ------------------------------------------------------------- documents */

for (const locale of LOCALES) {
  const dir = path.join(docsDir, locale);
  if (!existsSync(dir)) {
    fail(`docs/${locale} — missing documentation directory`);
    continue;
  }
  const files = readdirSync(dir).filter((name) => name.endsWith(".md"));
  for (const slug of DOC_SLUGS) {
    if (!files.includes(`${slug}.md`)) {
      fail(`docs/${locale}/${slug}.md — missing`);
      continue;
    }
    const raw = readFileSync(path.join(dir, `${slug}.md`), "utf8");
    const front = parseFrontmatter(raw);
    for (const field of ["title", "description", "minutes"]) {
      if (!front[field]) fail(`docs/${locale}/${slug}.md — frontmatter "${field}" missing`);
    }
    const words = raw.split(/\s+/).filter(Boolean).length;
    if (words < 200) {
      warnings.push(`docs/${locale}/${slug}.md — only ${words} words`);
    }
    if (/\b(TODO|FIXME):|\blorem ipsum\b/i.test(raw)) {
      fail(`docs/${locale}/${slug}.md — placeholder copy left in document`);
    }
  }
  for (const file of files) {
    const slug = file.replace(/\.md$/, "");
    if (!(DOC_SLUGS as readonly string[]).includes(slug)) {
      warnings.push(`docs/${locale}/${file} — not listed in DOC_SLUGS, will not be routed`);
    }
  }
}

/* ----------------------------------------------------------------- report */

const summary = `${checks} shape checks across ${LOCALES.length} locales`;

if (warnings.length) {
  console.log(`\n⚠ ${warnings.length} warning(s):`);
  for (const warning of warnings) console.log(`  - ${warning}`);
}

if (errors.length) {
  console.error(`\n✖ ${errors.length} content error(s) (${summary}):`);
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

console.log(`✔ content contract OK — ${summary}, ${DOC_SLUGS.length} documents × ${LOCALES.length} locales`);
