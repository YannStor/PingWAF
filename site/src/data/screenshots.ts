import type { ImageMetadata } from "astro";
import type { ScreenshotKey } from "../content/schema";

import access from "../assets/screenshots/access.png";
import agents from "../assets/screenshots/agents.png";
import bot from "../assets/screenshots/bot.png";
import caching from "../assets/screenshots/caching.png";
import cc from "../assets/screenshots/cc.png";
import configVersions from "../assets/screenshots/configVersions.png";
import dashboard from "../assets/screenshots/dashboard.png";
import login from "../assets/screenshots/login.png";
import logs from "../assets/screenshots/logs.png";
import sites from "../assets/screenshots/sites.png";
import ssl from "../assets/screenshots/ssl.png";
import waf from "../assets/screenshots/waf.png";

/**
 * Screenshot manifest — the only place that knows a screenshot's file.
 *
 * Files are produced by `npm run capture` (see `scripts/capture-screenshots.mjs`)
 * and imported here so Astro can emit AVIF/WebP variants at build time.
 * Content files reference screenshots by key only.
 */
export const SCREENSHOT_IMAGES: Record<ScreenshotKey, ImageMetadata> = {
  dashboard,
  sites,
  login,
  waf,
  cc,
  bot,
  access,
  caching,
  ssl,
  logs,
  agents,
  configVersions,
};
