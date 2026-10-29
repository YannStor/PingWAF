// @ts-check
import { defineConfig } from "astro/config";

/**
 * PingWAF official portal.
 *
 * Deployed to GitHub Pages as a *project* page, so every URL and asset lives
 * under `/PingWAF/`. Keep this in sync with `.github/workflows/pages.yml`.
 *
 * Nothing here may depend on a server: the output is a pure static directory
 * (`dist/`) served by GitHub Pages' CDN — no SSR adapter, no runtime.
 */
export default defineConfig({
  site: "https://shuaizend.github.io",
  base: "/PingWAF/",
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
