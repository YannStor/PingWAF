# PingWAF official site

Static, multilingual portal for PingWAF, built with [Astro](https://astro.build)
and deployed to **Cloudflare** as the Worker `pingwaf`, serving static assets
from `dist/` (Workers Builds, GitHub integration).

Everything here is output as plain HTML/CSS with a few kilobytes of inline
JavaScript — no server runtime, no API calls, no external fonts. The dashboard
screenshots are real captures of `web/dist` and are optimised at build time.

## Layout

| Path | Purpose |
| --- | --- |
| `astro.config.mjs` | Static output, `site`/`base` env hooks, Shiki themes |
| `wrangler.toml` | Worker name and `[assets]` config (`dist`, `404-page` handling) |
| `public/_headers` | Security headers plus immutable caching for `/_astro/*` |
| `public/_redirects` | Canonical entry point (`/index.html` → `/`) |
| `src/pages/` | Routes: English at the root, `[locale]/` mirrors for zh/es/fr/ja |
| `src/pages/404.astro` | Not-found page, served via `not_found_handling = "404-page"` |
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

## Local development

```bash
cd site
npm ci
npm run dev          # http://localhost:4321/
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
  resolved with `href()` / `resolveLink()` so the deployment base and locale
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

## Build

```bash
npm run build      # → site/dist
npm run preview    # serve dist locally at http://localhost:4321/
```

`dist/` is a self-contained static bundle: HTML, hashed `/_astro/*` assets,
`404.html`, `_headers` and `_redirects`. It is served from the domain root, so
`base` is `/`; set `SITE_BASE=/something/` when auditing a sub-path deployment.

## Deployment

Production is the Cloudflare **Worker** `pingwaf`, connected to this GitHub
repository through Workers Builds. Cloudflare builds and deploys on its own —
no GitHub Actions deployment runs in the normal flow.

The Worker has no script: `wrangler.toml` declares `[assets] directory =
"./dist"`, so the upload is pure static hosting, and `_headers` / `_redirects`
inside `dist` are honoured by Workers static assets.

### Build settings (Dashboard → Workers & Pages → pingwaf → Settings → Build)

| Setting | Value |
| --- | --- |
| Git branch | `main` (production branch) |
| Root directory | `site` |
| Build command | `npm run build` |
| Deploy command | `npx wrangler deploy` |
| Build variable | `SITE_URL=https://<production host>`, set for Build and Preview |

Three details break the deploy if they drift:

- **Deploy command must be the Workers one.** `npx wrangler pages deploy …`
  calls the Pages API and fails with `Authentication error [code: 10000]`,
  because the build environment's token is scoped to Workers, not Pages.
- **Never put `pages_build_output_dir` back in `wrangler.toml`.** Wrangler then
  treats the config as a Pages project and `wrangler deploy` stops with
  `Missing entry-point to Worker script or to assets directory`.
- **`name` must equal the Cloudflare project name** (`pingwaf`).

Pushes to `main` deploy to production; pushes to other branches produce preview
versions, which is a cheap way to review a locale or layout change.

### Optional: manual deploy from GitHub Actions

`.github/workflows/cloudflare-deploy.yml` runs only on `workflow_dispatch`, so
it never races Workers Builds. Use it when the Cloudflare connection is
unavailable or an older commit must be rebuilt; it needs two secrets:

| Secret | Value |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | API token with **Workers Scripts: Edit** on the account |
| `CLOUDFLARE_ACCOUNT_ID` | Account id (visible in the dashboard URL) |

### Manual deploy from a workstation

```bash
cd site
npm run build
npx wrangler deploy
```

### Custom domain and `SITE_URL`

Add the hostname under **Worker → Settings → Domains & Routes → Custom domain**
(Cloudflare issues the certificate), then set the `SITE_URL` build variable to
that hostname and redeploy. Without `SITE_URL`, canonical, hreflang and Open
Graph URLs fall back to the placeholder `https://pingwaf.example.com` and the
build prints a warning:

```bash
SITE_URL=https://pingwaf.example.com npm run build   # same result locally
```

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `check:links` reports "ignores the / base path" | A raw `href="/…"` was used instead of `href()` / `resolveLink()` |
| `check:content` reports an unexpected key | A locale file drifted from `src/content/schema.ts`; change the schema first |
| Canonical URLs point at `pingwaf.example.com` | `SITE_URL` build variable is not set |
| Screenshots look stale | Re-run `npm run capture` after `make build-web` |
| Deploy fails with `Authentication error [code: 10000]` | Deploy command is `wrangler pages deploy`; switch it to `wrangler deploy` |
| Deploy fails with `Missing entry-point to Worker script` | `wrangler.toml` still contains `pages_build_output_dir` |
| Deploy fails with 401 (manual workflow) | `CLOUDFLARE_API_TOKEN` lacks **Workers Scripts: Edit** |
| Cloudflare rejects the build with a name mismatch | `wrangler.toml` `name` differs from the Worker name |
