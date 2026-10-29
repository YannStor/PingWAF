import { DEFAULT_LOCALE, isLocale, LOCALES, type Locale } from "../i18n/config";
import type {
  DocsContent,
  FeaturesContent,
  IntroContent,
  LocaleBundle,
  QuickStartContent,
} from "./schema";

/**
 * Every module is discovered per locale, so a translator adding e.g.
 * `src/content/zh/features.ts` is picked up automatically: no shared registry
 * file to edit, no merge conflicts between module owners.
 */
const introModules = import.meta.glob<{ default: IntroContent }>("./*/intro.ts", {
  eager: true,
});
const featureModules = import.meta.glob<{ default: FeaturesContent }>("./*/features.ts", {
  eager: true,
});
const quickstartModules = import.meta.glob<{ default: QuickStartContent }>(
  "./*/quickstart.ts",
  { eager: true },
);
const docsModules = import.meta.glob<{ default: DocsContent }>("./*/docs.ts", {
  eager: true,
});

function indexByLocale<T>(modules: Record<string, { default: T }>): Map<Locale, T> {
  const map = new Map<Locale, T>();
  for (const [file, mod] of Object.entries(modules)) {
    const segment = file.split("/")[1] ?? "";
    if (isLocale(segment) && mod?.default) map.set(segment, mod.default);
  }
  return map;
}

const intros = indexByLocale(introModules);
const features = indexByLocale(featureModules);
const quickstarts = indexByLocale(quickstartModules);
const docs = indexByLocale(docsModules);

function requireModule<T>(map: Map<Locale, T>, name: string): T {
  const value = map.get(DEFAULT_LOCALE);
  if (!value) {
    throw new Error(
      `Content registry: src/content/${DEFAULT_LOCALE}/${name}.ts is required.`,
    );
  }
  return value;
}

const enIntro = requireModule(intros, "intro");
const enFeatures = requireModule(features, "features");
const enQuickstart = requireModule(quickstarts, "quickstart");
const enDocs = requireModule(docs, "docs");

const bundles = new Map<Locale, LocaleBundle>(
  LOCALES.map((locale) => [
    locale,
    {
      intro: intros.get(locale) ?? enIntro,
      features: features.get(locale) ?? enFeatures,
      quickstart: quickstarts.get(locale) ?? enQuickstart,
      docs: docs.get(locale) ?? enDocs,
    },
  ]),
);

/** Content bundle for a locale, falling back to English per module. */
export function getContent(locale: Locale): LocaleBundle {
  return bundles.get(locale) ?? bundles.get(DEFAULT_LOCALE)!;
}

/** Locales with at least one translated module (used by build checks). */
export function translatedLocales(): Locale[] {
  return LOCALES.filter(
    (locale) =>
      intros.has(locale) && features.has(locale) && quickstarts.has(locale) && docs.has(locale),
  );
}
