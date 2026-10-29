// @ts-check
import { defineConfig } from "astro/config";

/**
 * PingWAF official portal.
 *
 * Deployed as a Cloudflare Worker that serves static assets from `dist/`
 * (Workers Builds → GitHub integration → `wrangler deploy`). The project is
 * served at the domain root, so `base` stays `/`.
 *
 * `SITE_URL` must be set to the production hostname (`*.workers.dev` or the
 * custom domain) so canonical, hreflang and Open Graph URLs are absolute and
 * correct; it is read from the build environment, not hard-coded.
 *
 * Nothing here may depend on a server: the output is a pure static directory
 * — no SSR adapter, no runtime.
 */
const FALLBACK_SITE = "https://pingwaf.example.com";
const site = process.env.SITE_URL || FALLBACK_SITE;
const base = process.env.SITE_BASE ?? "/";

if (!process.env.SITE_URL) {
  console.warn(
    `[site] SITE_URL is not set — canonical/OG URLs fall back to ${FALLBACK_SITE}.`,
  );
}

export default defineConfig({
  site,
  base,
  output: "static",
  trailingSlash: "always",
  build: {
    format: "directory",
    inlineStylesheets: "auto",
  },
  prefetch: false,
  devToolbar: { enabled: false },
  markdown: {
    shikiConfig: {
      themes: {
        light: "github-light",
        dark: "github-dark-dimmed",
      },
      // Emit `--shiki-light` / `--shiki-dark` CSS variables instead of inline
      // colours so the theme toggle in `global.css` can switch them.
      defaultColor: false,
      wrap: false,
    },
  },
  vite: {
    build: {
      // Screenshots are hashed and immutable; keep the HTML/CSS budget small.
      assetsInlineLimit: 2048,
    },
  },
});
