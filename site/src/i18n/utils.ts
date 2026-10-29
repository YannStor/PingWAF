import {
  DEFAULT_LOCALE,
  LOCALES,
  LOCALE_META,
  PREFIXED_LOCALES,
  type Locale,
} from "./config";

/** Build-time base path, always with a trailing slash (`/` on Cloudflare Pages). */
const BASE = import.meta.env.BASE_URL.endsWith("/")
  ? import.meta.env.BASE_URL
  : `${import.meta.env.BASE_URL}/`;

/**
 * Normalize a site-relative path: leading slash, trailing slash, no locale.
 * `""`, `"features"`, `"/features"` → `"/features/"`; `"/"` stays `"/"`.
 */
export function normalizePath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed || trimmed === "/") return "/";
  const withLeading = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeading.endsWith("/") ? withLeading : `${withLeading}/`;
}

/**
 * Turn a locale-less path into a fully qualified href for `locale`,
 * including the deployment base path.
 *
 *   href("/features/", "zh") → "/zh/features/"
 *   href("/", "en")          → "/"
 */
export function href(path: string, locale: Locale = DEFAULT_LOCALE): string {
  const normalized = normalizePath(path);
  const prefix = locale === DEFAULT_LOCALE ? "" : `${locale}/`;
  return `${BASE}${prefix}${normalized.slice(1)}`;
}

/**
 * Resolve a content link: absolute URLs, anchors and mailto pass through,
 * site-relative paths get the locale prefix and deployment base.
 */
export function resolveLink(path: string, locale: Locale = DEFAULT_LOCALE): string {
  const isAbsolute = /^(?:[a-z]+:|#|\/\/)/i.test(path);
  if (isAbsolute && !path.startsWith(BASE)) return path;
  return href(path, locale);
}

/** Absolute URL for canonical links / Open Graph. */
export function absoluteUrl(path: string, locale: Locale = DEFAULT_LOCALE): string {
  const site = import.meta.env.SITE ?? "https://pingwaf.example.com";
  return new URL(href(path, locale), site).toString();
}

/** Every locale variant of a page, in `LOCALES` order. */
export function alternates(
  path: string,
): Array<{ locale: Locale; href: string; htmlLang: string }> {
  return LOCALES.map((locale) => ({
    locale,
    href: href(path, locale),
    htmlLang: LOCALE_META[locale].htmlLang,
  }));
}

/** Path segment used by a locale (`""` for the default locale). */
export function localePrefix(locale: Locale): string {
  return locale === DEFAULT_LOCALE ? "" : locale;
}

/**
 * Resolve the locale from a URL pathname (used by the dev-time router and by
 * the language switcher running on the client).
 */
export function localeFromPathname(pathname: string): Locale {
  const rest = pathname.startsWith(BASE) ? pathname.slice(BASE.length) : pathname;
  const first = rest.split("/")[0] ?? "";
  return (PREFIXED_LOCALES as readonly string[]).includes(first)
    ? (first as Locale)
    : DEFAULT_LOCALE;
}

/**
 * Inline script that redirects first-time visitors on the landing page to the
 * locale matching their browser. Only runs on `/` so deep links stay stable.
 *
 * Priority: explicit choice stored by the switcher → `navigator.languages`.
 */
export function localeDetectScript(): string {
  const prefixMap: Record<string, Locale> = {};
  for (const locale of PREFIXED_LOCALES) {
    for (const prefix of LOCALE_META[locale].detect) {
      prefixMap[prefix] = locale;
    }
  }

  return `(function(){try{
var base=${JSON.stringify(BASE)},map=${JSON.stringify(prefixMap)},known=${JSON.stringify(LOCALES)};
var path=location.pathname;
if(path!==base&&path!==base+"index.html")return;
var stored=null;
try{stored=localStorage.getItem("pw.locale");}catch(e){}
var target=null;
if(stored&&known.indexOf(stored)!==-1){
  // An explicit choice always wins — including "en", which must not bounce back.
  target=stored===${JSON.stringify(DEFAULT_LOCALE)}?null:stored;
}else{
  var langs=navigator.languages||[navigator.language||"en"];
  for(var i=0;i<langs.length;i++){
    var short=String(langs[i]||"").toLowerCase().split("-")[0];
    if(map[short]){target=map[short];break;}
  }
}
if(target){location.replace(base+target+"/");}
}catch(e){}})();`;
}

/** Inline script that applies the stored/system theme before first paint. */
export function themeInitScript(): string {
  return `(function(){try{
var stored=null;try{stored=localStorage.getItem("pw.theme");}catch(e){}
var dark=stored?stored==="dark":window.matchMedia("(prefers-color-scheme: dark)").matches;
document.documentElement.dataset.theme=dark?"dark":"light";
}catch(e){document.documentElement.dataset.theme="light";}})();`;
}

/** Inline script that persists an explicit locale choice made in the switcher. */
export function localePersistScript(): string {
  return `(function(){document.addEventListener("click",function(ev){
var el=ev.target;
while(el&&el!==document){if(el.getAttribute&&el.hasAttribute("data-locale-link")){
try{localStorage.setItem("pw.locale",el.getAttribute("data-locale"));}catch(e){}
return;}el=el.parentNode;}
});})();`;
}
