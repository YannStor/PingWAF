import type { QuickStartContent } from "../schema";

const quickstart = {
  meta: {
    title: "Démarrage — PingWAF",
    description:
      "Lancez PingWAF avec Docker Compose ou compilez-le, connectez-vous, ajoutez votre premier site et appliquez des règles en périphérie.",
  },
  hero: {
    eyebrow: "Démarrage",
    title: "En marche en cinq minutes, protégé en dix",
    lead: "Deux chemins officiels : la pile compose fournie pour évaluer, ou une compilation maison pour la production.",
    badges: [
      { icon: "container", label: "Voie A", value: "Docker Compose" },
      { icon: "code", label: "Voie B", value: "Compiler" },
      { icon: "clock", label: "Temps", value: "~5 minutes" },
      { icon: "database", label: "Stockage", value: "PostgreSQL 14+" },
    ],
    toc: [
      { id: "prerequisites", label: "Prérequis" },
      { id: "docker", label: "Docker Compose" },
      { id: "source", label: "Depuis les sources" },
      { id: "credentials", label: "Première connexion" },
      { id: "next", label: "Étapes suivantes" },
      { id: "troubleshooting", label: "Dépannage" },
    ],
  },
  prereq: {
    title: "Avant de commencer",
    lead: "La voie compose ne demande que Docker ; compiler exige Rust, Node et protoc.",
    items: [
      {
        label: "Docker",
        value: "Engine 24+ avec Compose v2",
        note: "Démarre le plan de contrôle, un agent et PostgreSQL.",
      },
      {
        label: "PostgreSQL",
        value: "14+ (16 recommandé)",
        note: "Le plan de contrôle y stocke sites, règles et versions.",
      },
      {
        label: "Ports",
        value: "9080 · 9090 · 80 · 443",
        note: "9080 sert l'API et la console, 9090 le plan gRPC.",
      },
      {
        label: "TLS",
        value: "Auto-signé au premier démarrage",
        note: "Remplacez-le ou faites-lui confiance avant d'exposer la console.",
      },
    ],
  },
  paths: {
    docker: {
      id: "docker",
      title: "Docker Compose",
      lead: "Le compose démarre PingWAF en mode all-in-one à côté de PostgreSQL avec l'image publiée.",
      steps: [
        {
          title: "Clonez le dépôt",
          body: "Le compose et le TOML d'exemple sont à la racine du dépôt.",
          code: {
            lang: "bash",
            code: "git clone https://github.com/shuaiZend/PingWAF.git\ncd PingWAF",
          },
        },
        {
          title: "Démarrez la pile",
          body: "Définissez JWT_SECRET et ADMIN_PASSWORD si l'hôte est joignable de l'extérieur.",
          code: {
            lang: "bash",
            code: "export JWT_SECRET=\"$(openssl rand -hex 32)\"\nexport ADMIN_PASSWORD=\"$(openssl rand -hex 16)\"\ndocker compose up -d",
          },
        },
        {
          title: "Ouvrez la console",
          body: "La console sert du HTTPS avec un certificat auto-signé généré au premier démarrage ; le navigateur alertera jusqu'à ce que vous le remplaciez.",
          code: {
            lang: "bash",
            code: "curl --connect-timeout 2 --max-time 3 http://localhost:9080/healthz\n# {\"status\":\"ok\",\"database\":\"up\"}",
          },
        },
        {
          title: "Ajoutez un premier site",
          body: "Créez un site avec le domaine pointé vers l'agent, puis activez uniquement les protections voulues.",
        },
      ],
      note: "Les binaires publiés ciblent Linux amd64/arm64 ; l'image Docker couvre les deux.",
      shot: {
        key: "sites",
        url: "localhost:9080/sites",
        caption: "La liste des sites est le point de départ : une ligne par domaine.",
        alt: "Liste des sites dans la console avec trafic et état de protection",
      },
    },
    source: {
      id: "source",
      title: "Compiler depuis les sources",
      lead: "Utile pour une compilation sur mesure ou un binaire auditable.",
      steps: [
        {
          title: "Installez la chaîne d'outils",
          body: "protoc est obligatoire : sans lui, le crate proto bascule sur des fichiers factices et la compilation échoue.",
          code: {
            lang: "bash",
            code: "# macOS\nbrew install protobuf\n\n# Debian / Ubuntu\nsudo apt install protobuf-compiler cmake",
          },
        },
        {
          title: "Compilez la console",
          body: "La console est embarquée dans le binaire, elle doit donc être compilée en premier.",
          code: {
            lang: "bash",
            code: "cd web && npm ci && npm run build && cd ..",
          },
        },
        {
          title: "Compilez le binaire",
          body: "La feature full inclut le moteur WAF, les défis et l'automatisation des certificats.",
          code: {
            lang: "bash",
            code: "cargo build --release --bin pingwaf --features full",
          },
        },
        {
          title: "Lancez en all-in-one",
          body: "Pointez vers une instance PostgreSQL ; le schéma est créé au premier démarrage.",
          code: {
            lang: "bash",
            code: "./target/release/pingwaf all-in-one \\\n  --db-url \"postgres://pingwaf:pingwaf@localhost:5432/pingwaf\"",
          },
        },
      ],
      note: "Sur Linux, install.sh (--mode all-in-one) évite la compilation.",
      shot: {
        key: "agents",
        url: "localhost:9080/agents",
        caption: "Une compilation maison peut servir de plan de contrôle puis enrôler des agents.",
        alt: "Page des agents avec les nœuds de périphérie enrôlés et leur heartbeat",
      },
    },
  },
  credentials: {
    title: "Première connexion",
    lead: "Le plan de contrôle crée un administrateur au premier démarrage, et la console impose un changement de mot de passe.",
    rows: [
      { label: "Console", value: "https://localhost:9080" },
      { label: "E-mail", value: "admin@pingwaf.local" },
      { label: "Mot de passe", value: "pingwaf123" },
      { label: "Secret JWT", value: "≥ 16 caractères" },
    ],
    warning: {
      title: "Changez les valeurs par défaut avant toute exposition",
      body: "PINGWAF_JWT_SECRET et PINGWAF_ADMIN_PASSWORD ont des valeurs fonctionnelles. Définissez-les, passez PINGWAF_ALLOW_REGISTRATION à false et gardez 9080 sur un réseau privé ou un VPN.",
    },
    shot: {
      key: "login",
      url: "localhost:9080/login",
      caption: "Connectez-vous avec le compte administrateur initial ; les passkeys s'ajoutent ensuite.",
      alt: "Page de connexion PingWAF avec champs e-mail et mot de passe",
    },
  },
  next: {
    title: "Étapes suivantes",
    lead: "Une fois le plan de contrôle joignable, tout le reste est de la configuration.",
    cards: [
      {
        icon: "globe",
        title: "Créez un site",
        body: "Un site relie un domaine aux pools d'origine, aux routes et aux protections activées.",
        link: { label: "Modèle de site", path: "/docs/architecture/" },
      },
      {
        icon: "network",
        title: "Connectez des agents",
        body: "Lancez pingwaf server sur le nœud de contrôle et pingwaf agent sur chaque nœud de périphérie ; ils s'enregistrent sur gRPC :9090.",
        link: { label: "Déploiement distribué", path: "/docs/deployment/" },
      },
      {
        icon: "shield-check",
        title: "Activez les protections",
        body: "Activez le moteur WAF, le bouclier CC ou la politique anti-bots par site : rien ne s'applique avant.",
        link: { label: "Capacités", path: "/features/" },
      },
      {
        icon: "activity",
        title: "Exportez les journaux",
        body: "Envoyez les journaux vers Elasticsearch et conservez les captures dans PostgreSQL pour rejouer.",
        link: { label: "Observabilité", path: "/features/#observability" },
      },
    ],
  },
  troubleshooting: {
    title: "Si le démarrage échoue",
    items: [
      {
        q: "La compilation échoue dans pingwaf-proto",
        a: "protoc manque. Installez protobuf-compiler (ou brew install protobuf) puis recompilez : sans lui le crate utilise des fichiers factices.",
      },
      {
        q: "Le navigateur refuse le certificat",
        a: "La console utilise HTTPS avec un certificat auto-signé. Faites confiance au certificat téléchargé ou importez le vôtre via Réglages → HTTPS du plan de contrôle ; renseignez PINGWAF_TLS_SANS.",
      },
      {
        q: "Un agent n'apparaît jamais",
        a: "Vérifiez qu'il atteint le plan gRPC sur :9090 (PINGWAF_SERVER_URL) et qu'aucun pare-feu ni proxy TLS ne l'en empêche.",
      },
      {
        q: "Le port 443 reste fermé",
        a: "443 n'ouvre qu'après l'émission ou l'import d'un certificat ; avant cela l'agent ne sert qu'en HTTP sur 80.",
      },
    ],
  },
  cta: {
    title: "Besoin de la version longue ?",
    lead: "Les documents déploiement et architecture couvrent systemd, les topologies distribuées, la précédence de configuration et toutes les variables d'environnement.",
    primary: { label: "Guide de déploiement", path: "/docs/deployment/" },
    secondary: { label: "GitHub", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies QuickStartContent;

export default quickstart;
