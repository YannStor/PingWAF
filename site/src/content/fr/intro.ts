import type { IntroContent } from "../schema";

const intro = {
  meta: {
    title: "PingWAF — Pare-feu applicatif distribué sur Pingora",
    description:
      "WAF open source basé sur pingap et Cloudflare Pingora : un plan de contrôle, plusieurs agents en périphérie, détection sémantique, défense CC et anti-bots, TLS automatique et console intégrée.",
  },
  hero: {
    badges: ["Apache-2.0", "Rust · Pingora", "Auto-hébergé"],
    title: "Une protection de niveau Cloudflare pour",
    titleAccent: "votre propre infrastructure",
    lead: "PingWAF est un pare-feu applicatif distribué et administré de façon centralisée. Définissez sites, règles et politiques une fois dans le plan de contrôle ; chaque agent en périphérie les applique en quelques secondes, sans rechargement ni interruption.",
    primary: { label: "Démarrer en 5 minutes", path: "/quickstart/" },
    secondary: { label: "Lire la documentation", path: "/docs/" },
    stats: [
      { value: "4 phases", label: "Normaliser → signatures → expressions → score" },
      { value: "7 RPC", label: "Protocole gRPC du plan de contrôle" },
      { value: "5 fournisseurs", label: "Intégrations ACME DNS-01" },
    ],
    pills: [
      { icon: "shield-check", text: "SQLi · XSS · RCE · traversal" },
      { icon: "refresh", text: "Règles propagées en secondes" },
    ],
    shot: {
      key: "dashboard",
      url: "localhost:9080/dashboard",
      caption: "Trafic, attaques et santé des agents dans la console intégrée.",
      alt: "Tableau de bord PingWAF avec analyses de requêtes, tendances d'attaque et état des agents",
    },
  },
  proof: [
    {
      value: "Apache-2.0",
      label: "Open source de bout en bout",
      note: "Aucune facturation à la requête, aucune dépendance hébergée.",
    },
    {
      value: "Rust",
      label: "Plan de données à mémoire sûre",
      note: "Pingora + tokio dans un binaire autonome.",
    },
    {
      value: "PostgreSQL",
      label: "État du plan de contrôle",
      note: "Sites, règles, instantanés de configuration et audit.",
    },
    {
      value: "gRPC",
      label: "Synchronisation à chaud",
      note: "Flux bidirectionnels, sans redémarrage.",
    },
  ],
  architecture: {
    eyebrow: "Architecture",
    title: "Un plan de contrôle, plusieurs agents",
    lead: "Le plan de contrôle est la seule source de vérité. Les agents ne font que transporter le trafic et appliquer les politiques : le plan de données peut donc monter en charge sans toucher à l'état.",
    points: [
      {
        title: "Le plan de contrôle détient l'état",
        body: "Sites, règles, certificats et versions de configuration vivent dans PostgreSQL, derrière une API REST Axum, un service gRPC tonic et la console intégrée.",
      },
      {
        title: "Les agents appliquent en périphérie",
        body: "Chaque agent conserve un cache de règles sur disque et continue de servir avec la dernière politique connue même si le plan de contrôle est injoignable.",
      },
      {
        title: "Les changements arrivent sans rechargement",
        body: "SyncRules pousse un nouveau paquet sur le flux bidirectionnel existant ; l'agent l'échange en mémoire pendant que le trafic continue.",
      },
    ],
    diagram: {
      lanes: [
        {
          label: "Clients",
          nodes: [{ title: "Navigateur / client API", meta: "HTTPS" }],
        },
        {
          label: "Plan de données · agent",
          nodes: [
            { title: "Agent périphérie A", meta: ":80 / :443", accent: true },
            { title: "Agent périphérie B", meta: ":80 / :443", accent: true },
          ],
        },
        {
          label: "Plan de contrôle · serveur",
          nodes: [
            { title: "REST + console", meta: ":9080" },
            { title: "gRPC ControlPlane", meta: ":9090" },
            { title: "PostgreSQL", meta: "SeaORM" },
            { title: "Elasticsearch", meta: "optionnel" },
          ],
        },
        {
          label: "Origine",
          nodes: [{ title: "Pools d'origine", meta: "HTTP / HTTPS" }],
        },
      ],
      links: [
        "HTTP / HTTPS",
        "Flux gRPC · Heartbeat · ShipLogs · SyncRules",
        "requêtes relayées",
      ],
    },
    link: { label: "Comprendre le plan de contrôle", path: "/docs/architecture/" },
  },
  capabilities: {
    eyebrow: "Capacités",
    title: "Défense en profondeur, désactivée par défaut",
    lead: "Toutes les protections sont livrées désactivées et s'activent par site : rien ne modifie votre trafic tant que vous ne le demandez pas.",
    items: [
      {
        icon: "shield",
        title: "Moteur WAF sémantique",
        body: "Détection par signatures et heuristiques des injections SQL, XSS, RCE, traversée de répertoire et injection de commandes.",
        points: [
          "Heuristiques libinjection + Aho-Corasick",
          "Règles d'expression façon Cloudflare",
          "Verdicts Pass / Monitor / Block / Challenge",
        ],
        link: { label: "Moteur WAF", path: "/features/#waf-engine" },
      },
      {
        icon: "bot",
        title: "Défense CC et anti-bots",
        body: "Absorbez les pics et distinguez les navigateurs réels des scripts grâce à des défis successifs.",
        points: [
          "Bouclier JavaScript de 5 secondes et preuve de travail",
          "Cookies de passage signés en HMAC",
          "Liste de bots vérifiés par site",
        ],
        link: { label: "CC et bots", path: "/features/#cc-bot" },
      },
      {
        icon: "key",
        title: "Contrôle d'accès",
        body: "Décidez qui atteint l'origine selon l'adresse, la région et la dimension de la requête.",
        points: [
          "Règles IP avec CIDR et import CSV",
          "Blocage géographique par pays et ASN",
          "Limites par IP, hôte, chemin ou en-tête",
        ],
        link: { label: "Contrôle d'accès", path: "/features/#access-control" },
      },
      {
        icon: "route",
        title: "Trafic et cache",
        body: "Routez, répartissez et cachez sans quitter la console.",
        points: [
          "Pools d'origine avec cinq stratégies",
          "Routes par préfixe, exactes et regex",
          "Cache en périphérie avec quotas et SWR",
        ],
        link: { label: "Trafic et cache", path: "/features/#traffic-caching" },
      },
      {
        icon: "lock",
        title: "TLS et certificats",
        body: "Des certificats émis en périphérie et visibles depuis un seul endroit.",
        points: [
          "ACME HTTP-01 et DNS-01 avec renouvellement",
          "État du certificat par site dans le heartbeat",
          "Émission et révocation immédiate mTLS",
        ],
        link: { label: "TLS et certificats", path: "/features/#tls" },
      },
      {
        icon: "activity",
        title: "Observabilité et console",
        body: "Chaque requête est auditable et chaque changement de configuration réversible.",
        points: [
          "Journaux dans Elasticsearch avec tampon WAL",
          "Capture des requêtes et réponses pour rejouer",
          "Versions de configuration avec diff et rollback",
        ],
        link: { label: "Observabilité", path: "/features/#observability" },
      },
    ],
    link: { label: "Toutes les capacités", path: "/features/" },
  },
  showcase: {
    eyebrow: "Dans la console",
    title: "Exploiter sans pile supplémentaire",
    lead: "La console est compilée dans le binaire : ce que vous voyez correspond exactement à ce que sait le plan de contrôle.",
    shots: [
      {
        key: "waf",
        url: "localhost:9080/sites/example.com/security/protection",
        caption: "Les règles WAF et les défis CC se configurent par site.",
        alt: "Page de protection du site avec onglets de règles WAF et réglages de défi",
      },
      {
        key: "logs",
        url: "localhost:9080/logs",
        caption: "Les journaux de requêtes portent verdict, score et règle appliquée.",
        alt: "Liste des journaux de requêtes avec verdicts et règles déclenchées",
      },
      {
        key: "ssl",
        url: "localhost:9080/sites/example.com/ssl",
        caption: "État du certificat et événements ACME pour chaque site.",
        alt: "Page TLS du site avec état du certificat et événements ACME",
      },
    ],
  },
  quickstart: {
    eyebrow: "Démarrage",
    title: "De zéro à un site protégé",
    lead: "Le fichier compose fourni démarre le plan de contrôle, un agent et PostgreSQL. Connectez-vous, ajoutez un site, et la périphérie applique les politiques.",
    steps: [
      { title: "Démarrez la pile", body: "docker compose up -d récupère l'image publiée et démarre PostgreSQL." },
      { title: "Connectez-vous", body: "Ouvrez https://localhost:9080 avec le compte administrateur initial." },
      { title: "Ajoutez un site", body: "Pointez un domaine vers l'agent et activez les protections du site." },
    ],
    terminal: {
      title: "bash — pingwaf",
      lines: [
        "$ git clone https://github.com/shuaiZend/PingWAF.git",
        "$ cd PingWAF && docker compose up -d",
        "plan de contrôle  https://localhost:9080",
        "agent             :80 / :443",
        "postgres          :5432",
      ],
    },
    primary: { label: "Démarrage complet", path: "/quickstart/" },
    secondary: { label: "Guide de déploiement", path: "/docs/deployment/" },
  },
  cta: {
    title: "Un WAF que vous pouvez lire, auditer et posséder",
    lead: "Chaque règle, verdict et ligne de journal reste dans votre infrastructure, sous une licence qui vous permet de tout modifier.",
    primary: { label: "Commencer", path: "/quickstart/" },
    secondary: { label: "Étoile sur GitHub", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies IntroContent;

export default intro;
