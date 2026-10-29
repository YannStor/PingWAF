import type { IconName } from "../data/icons";

/**
 * Content contract.
 *
 * Every locale implements exactly these shapes, and `scripts/check-content.ts`
 * enforces key/array parity against English. Add a field here first, then fill
 * it in all five locales — never the other way around.
 */

export const ROUTES = {
  home: "/",
  features: "/features/",
  quickstart: "/quickstart/",
  docs: "/docs/",
} as const;

export const DOC_SLUGS = ["architecture", "deployment", "waf-engine", "api"] as const;
export type DocSlug = (typeof DOC_SLUGS)[number];

export function docPath(slug: DocSlug): string {
  return `${ROUTES.docs}${slug}/`;
}

/** Screenshots captured from the real dashboard by `npm run capture`. */
export const SCREENSHOT_KEYS = [
  "dashboard",
  "sites",
  "login",
  "waf",
  "cc",
  "bot",
  "access",
  "caching",
  "ssl",
  "logs",
  "agents",
  "configVersions",
] as const;
export type ScreenshotKey = (typeof SCREENSHOT_KEYS)[number];

export interface PageMeta {
  title: string;
  description: string;
}

export interface LinkRef {
  label: string;
  path: string;
}

export interface Shot {
  key: ScreenshotKey;
  /** Console URL shown in the browser chrome of the frame. */
  url: string;
  caption: string;
  alt: string;
}

/** Shared bottom-of-page call to action. */
export interface CtaContent {
  title: string;
  lead: string;
  primary: LinkRef;
  secondary: LinkRef;
}

/* ---------------------------------------------------------------- intro */

export interface DiagramLane {
  label: string;
  nodes: Array<{ title: string; meta: string; accent?: boolean }>;
}

export interface IntroContent {
  meta: PageMeta;
  hero: {
    badges: string[];
    title: string;
    titleAccent: string;
    lead: string;
    primary: LinkRef;
    secondary: LinkRef;
    stats: Array<{ value: string; label: string }>;
    pills: Array<{ icon: IconName; text: string }>;
    shot: Shot;
  };
  proof: Array<{ value: string; label: string; note: string }>;
  architecture: {
    eyebrow: string;
    title: string;
    lead: string;
    points: Array<{ title: string; body: string }>;
    diagram: {
      lanes: DiagramLane[];
      /** One label per gap between lanes (lanes.length - 1). */
      links: string[];
    };
    link: LinkRef;
  };
  capabilities: {
    eyebrow: string;
    title: string;
    lead: string;
    items: Array<{
      icon: IconName;
      title: string;
      body: string;
      points: string[];
      link?: LinkRef;
    }>;
    link: LinkRef;
  };
  showcase: {
    eyebrow: string;
    title: string;
    lead: string;
    shots: Shot[];
  };
  quickstart: {
    eyebrow: string;
    title: string;
    lead: string;
    steps: Array<{ title: string; body: string }>;
    terminal: { title: string; lines: string[] };
    primary: LinkRef;
    secondary: LinkRef;
  };
  cta: CtaContent;
}

/* ------------------------------------------------------------- features */

export interface FeatureGroup {
  id: string;
  icon: IconName;
  kicker: string;
  title: string;
  lead: string;
  points: string[];
  note?: string;
  shot: Shot;
}

export interface VerdictRow {
  verdict: "pass" | "monitor" | "block" | "challenge";
  label: string;
  meaning: string;
  action: string;
}

export interface FeaturesContent {
  meta: PageMeta;
  hero: {
    eyebrow: string;
    title: string;
    lead: string;
    toc: Array<{ id: string; label: string }>;
  };
  groups: FeatureGroup[];
  verdicts: {
    eyebrow: string;
    title: string;
    lead: string;
    columns: [string, string, string];
    rows: VerdictRow[];
  };
  cta: CtaContent;
}

/* ------------------------------------------------------------ quickstart */

export interface CodeSample {
  lang: string;
  filename?: string;
  code: string;
}

export interface Step {
  title: string;
  body?: string;
  code?: CodeSample;
}

export interface QuickStartContent {
  meta: PageMeta;
  hero: {
    eyebrow: string;
    title: string;
    lead: string;
    badges: Array<{ icon: IconName; label: string; value: string }>;
    toc: Array<{ id: string; label: string }>;
  };
  prereq: {
    title: string;
    lead: string;
    items: Array<{ label: string; value: string; note: string }>;
  };
  paths: {
    docker: { id: string; title: string; lead: string; steps: Step[]; note?: string; shot: Shot };
    source: { id: string; title: string; lead: string; steps: Step[]; note?: string; shot: Shot };
  };
  credentials: {
    title: string;
    lead: string;
    rows: Array<{ label: string; value: string }>;
    warning: { title: string; body: string };
    shot: Shot;
  };
  next: {
    title: string;
    lead: string;
    cards: Array<{ icon: IconName; title: string; body: string; link: LinkRef }>;
  };
  troubleshooting: {
    title: string;
    items: Array<{ q: string; a: string }>;
  };
  cta: CtaContent;
}

/* ----------------------------------------------------------------- docs */

export interface DocsContent {
  meta: PageMeta;
  hero: {
    eyebrow: string;
    title: string;
    lead: string;
  };
  cards: Array<{
    slug: DocSlug;
    icon: IconName;
    title: string;
    lead: string;
    minutes: number;
    topics: string[];
  }>;
  sidebarLabel: string;
  screenshot: Shot;
  github: {
    title: string;
    body: string;
    link: LinkRef;
  };
  backToHub: string;
  editLabel: string;
}

/* -------------------------------------------------------------- registry */

export interface LocaleBundle {
  intro: IntroContent;
  features: FeaturesContent;
  quickstart: QuickStartContent;
  docs: DocsContent;
}
