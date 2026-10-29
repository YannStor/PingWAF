// @ts-check
import { defineConfig } from "astro/config";

/**
 * PingWAF official portal.
 *
 * Deployed to Cloudflare Pages, which serves the project at the domain root,
 * so `base` stays `/`. Override `SITE_URL` when the production hostname changes
 * (custom domain, preview branch, local `astro build` for checking canonicals).
 *
 * Nothing here may depend on a server: the output is a pure static directory
 * (`dist/`) served by Cloudflare's edge — no SSR adapter, no runtime.
 */
const site = process.env.SITE_URL ?? "https://pingwaf.pages.dev";
const base = process.env.SITE_BASE ?? "/";

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
