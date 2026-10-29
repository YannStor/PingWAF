import type { Locale } from "./config";

/**
 * Chrome-level copy (navigation, buttons, footer, accessibility labels).
 * Module copy lives in `src/content/<locale>/*.ts`.
 */
export interface UiStrings {
  readonly nav: {
    readonly overview: string;
    readonly features: string;
    readonly quickstart: string;
    readonly docs: string;
  };
  readonly cta: {
    readonly getStarted: string;
    readonly readDocs: string;
    readonly viewGithub: string;
    readonly viewAllFeatures: string;
  };
  readonly common: {
    readonly language: string;
    readonly theme: string;
    readonly toggleTheme: string;
    readonly menu: string;
    readonly close: string;
    readonly copy: string;
    readonly copied: string;
    readonly onThisPage: string;
    readonly previous: string;
    readonly next: string;
    readonly editOnGithub: string;
    readonly minutes: string;
    readonly screenshot: string;
    readonly openImage: string;
    readonly skipToContent: string;
    readonly primaryNav: string;
    readonly footerNav: string;
    readonly externalLink: string;
    readonly breadcrumbHome: string;
  };
  readonly footer: {
    readonly tagline: string;
    readonly product: string;
    readonly resources: string;
    readonly community: string;
    readonly license: string;
    readonly builtWith: string;
    readonly copyright: string;
  };
}

const en: UiStrings = {
  nav: { overview: "Overview", features: "Features", quickstart: "Quick start", docs: "Docs" },
  cta: {
    getStarted: "Get started",
    readDocs: "Read the docs",
    viewGithub: "GitHub",
    viewAllFeatures: "All capabilities",
  },
  common: {
    language: "Language",
    theme: "Appearance",
    toggleTheme: "Toggle dark mode",
    menu: "Menu",
    close: "Close",
    copy: "Copy",
    copied: "Copied",
    onThisPage: "On this page",
    previous: "Previous",
    next: "Next",
    editOnGithub: "Edit this page on GitHub",
    minutes: "min read",
    screenshot: "PingWAF console screenshot",
    openImage: "Open full-size screenshot",
    skipToContent: "Skip to content",
    primaryNav: "Primary",
    footerNav: "Footer",
    externalLink: "opens in a new tab",
    breadcrumbHome: "Home",
  },
  footer: {
    tagline:
      "A distributed, centrally controlled Web Application Firewall built on Pingora.",
    product: "Product",
    resources: "Resources",
    community: "Community",
    license: "Apache-2.0 licensed",
    builtWith: "Rust · Pingora · React",
    copyright: "© 2026 PingWAF contributors",
  },
};

const zh: UiStrings = {
  nav: { overview: "概览", features: "核心特性", quickstart: "快速上手", docs: "文档" },
  cta: {
    getStarted: "立即开始",
    readDocs: "阅读文档",
    viewGithub: "GitHub",
    viewAllFeatures: "查看全部能力",
  },
  common: {
    language: "语言",
    theme: "外观",
    toggleTheme: "切换深色模式",
    menu: "菜单",
    close: "关闭",
    copy: "复制",
    copied: "已复制",
    onThisPage: "本页目录",
    previous: "上一篇",
    next: "下一篇",
    editOnGithub: "在 GitHub 上编辑此页",
    minutes: "分钟阅读",
    screenshot: "PingWAF 控制台截图",
    openImage: "查看原尺寸截图",
    skipToContent: "跳到正文",
    primaryNav: "主导航",
    footerNav: "页脚导航",
    externalLink: "在新标签页打开",
    breadcrumbHome: "首页",
  },
  footer: {
    tagline: "基于 Pingora 构建的分布式、集中管控 Web 应用防火墙。",
    product: "产品",
    resources: "资源",
    community: "社区",
    license: "Apache-2.0 许可",
    builtWith: "Rust · Pingora · React",
    copyright: "© 2026 PingWAF 贡献者",
  },
};

const es: UiStrings = {
  nav: {
    overview: "Resumen",
    features: "Funciones",
    quickstart: "Inicio rápido",
    docs: "Documentación",
  },
  cta: {
    getStarted: "Empezar",
    readDocs: "Leer la documentación",
    viewGithub: "GitHub",
    viewAllFeatures: "Ver todas las capacidades",
  },
  common: {
    language: "Idioma",
    theme: "Apariencia",
    toggleTheme: "Cambiar el modo oscuro",
    menu: "Menú",
    close: "Cerrar",
    copy: "Copiar",
    copied: "Copiado",
    onThisPage: "En esta página",
    previous: "Anterior",
    next: "Siguiente",
    editOnGithub: "Editar esta página en GitHub",
    minutes: "min de lectura",
    screenshot: "Captura de la consola de PingWAF",
    openImage: "Ver la captura a tamaño completo",
    skipToContent: "Ir al contenido",
    primaryNav: "Navegación principal",
    footerNav: "Navegación del pie",
    externalLink: "se abre en una pestaña nueva",
    breadcrumbHome: "Inicio",
  },
  footer: {
    tagline:
      "Un firewall de aplicaciones web distribuido y gestionado de forma centralizada sobre Pingora.",
    product: "Producto",
    resources: "Recursos",
    community: "Comunidad",
    license: "Licencia Apache-2.0",
    builtWith: "Rust · Pingora · React",
    copyright: "© 2026 colaboradores de PingWAF",
  },
};

const fr: UiStrings = {
  nav: {
    overview: "Aperçu",
    features: "Fonctionnalités",
    quickstart: "Démarrage",
    docs: "Documentation",
  },
  cta: {
    getStarted: "Commencer",
    readDocs: "Lire la documentation",
    viewGithub: "GitHub",
    viewAllFeatures: "Toutes les capacités",
  },
  common: {
    language: "Langue",
    theme: "Apparence",
    toggleTheme: "Basculer le mode sombre",
    menu: "Menu",
    close: "Fermer",
    copy: "Copier",
    copied: "Copié",
    onThisPage: "Sur cette page",
    previous: "Précédent",
    next: "Suivant",
    editOnGithub: "Modifier cette page sur GitHub",
    minutes: "min de lecture",
    screenshot: "Capture d'écran de la console PingWAF",
    openImage: "Voir la capture en taille réelle",
    skipToContent: "Aller au contenu",
    primaryNav: "Navigation principale",
    footerNav: "Navigation du pied de page",
    externalLink: "s'ouvre dans un nouvel onglet",
    breadcrumbHome: "Accueil",
  },
  footer: {
    tagline:
      "Un pare-feu applicatif web distribué et administré de façon centralisée, construit sur Pingora.",
    product: "Produit",
    resources: "Ressources",
    community: "Communauté",
    license: "Licence Apache-2.0",
    builtWith: "Rust · Pingora · React",
    copyright: "© 2026 contributeurs de PingWAF",
  },
};

const ja: UiStrings = {
  nav: { overview: "概要", features: "機能", quickstart: "クイックスタート", docs: "ドキュメント" },
  cta: {
    getStarted: "はじめる",
    readDocs: "ドキュメントを読む",
    viewGithub: "GitHub",
    viewAllFeatures: "すべての機能を見る",
  },
  common: {
    language: "言語",
    theme: "外観",
    toggleTheme: "ダークモードを切り替え",
    menu: "メニュー",
    close: "閉じる",
    copy: "コピー",
    copied: "コピーしました",
    onThisPage: "このページ",
    previous: "前へ",
    next: "次へ",
    editOnGithub: "GitHub でこのページを編集",
    minutes: "分で読めます",
    screenshot: "PingWAF コンソールのスクリーンショット",
    openImage: "元のサイズで表示",
    skipToContent: "本文へスキップ",
    primaryNav: "メインナビゲーション",
    footerNav: "フッターナビゲーション",
    externalLink: "新しいタブで開きます",
    breadcrumbHome: "ホーム",
  },
  footer: {
    tagline:
      "Pingora を基盤とした分散型・集中管理の Web アプリケーションファイアウォール。",
    product: "プロダクト",
    resources: "リソース",
    community: "コミュニティ",
    license: "Apache-2.0 ライセンス",
    builtWith: "Rust · Pingora · React",
    copyright: "© 2026 PingWAF コントリビューター",
  },
};

export const UI: Record<Locale, UiStrings> = { en, zh, es, fr, ja };

export function t(locale: Locale): UiStrings {
  return UI[locale];
}
