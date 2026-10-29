/**
 * Single source of truth for the portal's locale set.
 *
 * `en` is the default and lives at the site root (`/`); every other locale is
 * served from a prefix (`/zh/`, `/es/`, `/fr/`, `/ja/`). Nothing in the site
 * may hard-code a locale list — import from here.
 */
export const LOCALES = ["en", "zh", "es", "fr", "ja"] as const;

export type Locale = (typeof LOCALES)[number];

export const DEFAULT_LOCALE: Locale = "en";

/** Locales that live behind a path prefix (everything except the default). */
export const PREFIXED_LOCALES = LOCALES.filter(
  (locale): locale is Exclude<Locale, "en"> => locale !== DEFAULT_LOCALE,
);

export interface LocaleMeta {
  /** Native name shown in the switcher. */
  label: string;
  /** Two/three letter code shown next to the native name. */
  code: string;
  /** Value for `<html lang>`. */
  htmlLang: string;
  /** Open Graph locale identifier. */
  ogLocale: string;
  /** Text direction. All current locales are LTR. */
  dir: "ltr" | "rtl";
  /** BCP-47 prefixes used for `navigator.languages` detection. */
  detect: readonly string[];
}

export const LOCALE_META: Record<Locale, LocaleMeta> = {
  en: {
    label: "English",
    code: "EN",
    htmlLang: "en",
    ogLocale: "en_US",
    dir: "ltr",
    detect: ["en"],
  },
  zh: {
    label: "简体中文",
    code: "ZH",
    htmlLang: "zh-CN",
    ogLocale: "zh_CN",
    dir: "ltr",
    detect: ["zh"],
  },
  es: {
    label: "Español",
    code: "ES",
    htmlLang: "es",
    ogLocale: "es_ES",
    dir: "ltr",
    detect: ["es"],
  },
  fr: {
    label: "Français",
    code: "FR",
    htmlLang: "fr",
    ogLocale: "fr_FR",
    dir: "ltr",
    detect: ["fr"],
  },
  ja: {
    label: "日本語",
    code: "JA",
    htmlLang: "ja",
    ogLocale: "ja_JP",
    dir: "ltr",
    detect: ["ja"],
  },
};

export function isLocale(value: string): value is Locale {
  return (LOCALES as readonly string[]).includes(value);
}
