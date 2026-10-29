# PingWAF official site

Static, multilingual portal for PingWAF, built with [Astro](https://astro.build) and
deployed to GitHub Pages as a project page: <https://shuaizend.github.io/PingWAF/>.

Everything here is output as plain HTML/CSS with a few kilobytes of inline
JavaScript — no server runtime, no API calls, no external fonts. The dashboard
screenshots are real captures of `web/dist` and are optimised at build time.

## Layout

| Path | Purpose |
| --- | --- |
| `astro.config.mjs` | Static output, `base: /PingWAF/`, Shiki themes |
| `src/pages/` | Routes: English at the root, `[locale]/` mirrors for zh/es/fr/ja |
| `src/layouts/BaseLayout.astro` | `<head>`, hreflang/canonical/OG, theme + language scripts, header/footer |
| `src/layouts/DocsLayout.astro` | Three-column documentation shell with sidebar and page TOC |
| `src/components/` | Header, footer, screenshot frame, code block, section primitives |
| `src/content/<locale>/*.ts` | Typed marketing copy: `intro`, `features`, `quickstart`, `docs` |
| `src/content/docs/<locale>/*.md` | Long-form documentation (Content Collection) |
| `src/content/schema.ts` | **The content contract** — every locale implements these shapes |
| `src/content/index.ts` | Discovers locale modules at build time (no shared registry file) |
| `src/i18n/` | Locale list, UI strings, path helpers, detection/theme scripts |
| `src/styles/` | Design tokens copied from the dashboard plus portal layout |
| `src/assets/screenshots/` | Console screenshots, consumed through `astro:assets` |
| `src/data/screenshots.ts` | The only place that maps a screenshot key to a file |
| `scripts/capture-screenshots.mjs` | Serves `web/dist`, stubs `/api/v1`, captures the console |
| `scripts/check-content.ts` | Five-locale key/shape parity, links, docs and screenshot checks |
| `scripts/check-links.mjs` | Post-build internal link and asset audit |
| `public/` | `favicon.svg`, `og.png`, `.nojekyll` |

## Local development

```bash
cd site
npm ci
npm run dev          # http://localhost:4321/PingWAF/
npm run verify       # content contract + type check + build + link audit
```

`npm run verify` is the gate CI runs; keep it green before opening a PR.

## Content rules

- **English is the source of truth.** Edit `src/content/en/*.ts` first, then mirror
  the change in `zh`, `es`, `fr` and `ja`. `npm run check:content` fails when a key
  is missing, an array length differs, a placeholder (`TODO:`) survives, or a
  screenshot key/link points nowhere.
- Facts must be verifiable in the repository (`README*.md`, `docs/**`,
  `pingwaf-*/src`). Do not invent defaults, ports or endpoints.
- Keep commands, code samples, URLs, screenshot keys and `slug`/`id` values
  untranslated — the checker treats them as machine identifiers.
- Long-form pages live in `src/content/docs/<locale>/<slug>.md` with
  `title`, `description` and `minutes` frontmatter. Slugs are defined once in
  `src/content/schema.ts` (`DOC_SLUGS`), which also drives routes and the sidebar.
- Internal links are locale-less paths (`/features/`, `/docs/api/`) and are
  resolved with `href()` / `resolveLink()` so the `/PingWAF/` base and locale
  prefix are never dropped. Absolute URLs pass through untouched.

## Adding a language

1. Add the locale to `LOCALES` and `LOCALE_META` in `src/i18n/config.ts`
   (native label, `htmlLang`, Open Graph locale, detection prefixes).
2. Add `src/content/<locale>/{intro,features,quickstart,docs}.ts`, each
   `satisfies` the type from `src/content/schema.ts` and exporting it as default.
3. Translate `src/ui.ts` (nav, buttons, footer, accessibility labels).
4. Add `src/content/docs/<locale>/{architecture,deployment,waf-engine,api}.md`.
5. Run `npm run verify`. `hreflang`, canonical URLs and the switcher are generated
   from the locale list — no other file needs editing.

## Screenshots

```bash
npm run capture
```

The script serves the built dashboard (`web/dist`, build it with
`make build-web` first), fulfils every `/api/v1/**` request from
`scripts/fixtures.mjs`, logs in by injecting the session keys the console uses,
and writes 1440×900 @2x PNGs into `src/assets/screenshots/`. Recipes live in
`SHOTS` at the top of the script; all demo data is `example.com` plus RFC 5737
ranges.

For a real control plane:

```bash
E2E_ADMIN_EMAIL=admin@pingwaf.local E2E_ADMIN_PASSWORD='…' \
  npm run capture -- --live --base=https://localhost:9080
```

Screenshots are committed, so the site build never needs a browser. They are
imported through `src/data/screenshots.ts` and emitted as AVIF/WebP at build
time — never put them in `public/`.

## Build and deploy

```bash
npm run build      # → site/dist
npm run preview    # serve dist locally under /PingWAF/
```

`.github/workflows/pages.yml` builds and deploys on every push to `main` that
touches `site/**`, plus manual `workflow_dispatch`. It runs `check:content`,
`build` and `check:links` before uploading `site/dist`.

The base path is fixed to `/PingWAF/` because this is a project page. Serving it
from a custom domain would require changing `base` in `astro.config.mjs` and the
deployment base in the workflow.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `check:links` reports "ignores the /PingWAF/ base path" | A raw `href="/…"` was used instead of `href()` / `resolveLink()` |
| `check:content` reports an unexpected key | A locale file drifted from `src/content/schema.ts`; change the schema first |
| `hreflang` count mismatch | A page was added outside `BaseLayout` |
| Screenshots look stale | Re-run `npm run capture` after `make build-web` |
