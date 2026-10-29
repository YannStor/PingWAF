import type { DocsContent } from "../schema";

const docs = {
  meta: {
    title: "Documentation — PingWAF",
    description:
      "Architecture, déploiement, moteur WAF et API REST/gRPC : les quatre documents nécessaires pour exploiter PingWAF en production.",
  },
  hero: {
    eyebrow: "Documentation",
    title: "Les quatre documents qui expliquent PingWAF",
    lead: "Commencez par l'architecture pour évaluer, par le déploiement pour installer, et par le moteur WAF pour régler les règles.",
  },
  cards: [
    {
      slug: "architecture",
      icon: "network",
      title: "Architecture",
      lead: "Comment le plan de contrôle et le plan de données s'articulent, et ce que transporte gRPC.",
      minutes: 8,
      topics: ["plan de contrôle", "plan de données", "gRPC", "modes"],
    },
    {
      slug: "deployment",
      icon: "server",
      title: "Déploiement",
      lead: "All-in-one ou distribué, Docker et systemd, ports et précédence de configuration.",
      minutes: 10,
      topics: ["docker", "systemd", "ports", "environnement"],
    },
    {
      slug: "waf-engine",
      icon: "shield",
      title: "Moteur WAF",
      lead: "Le pipeline en quatre phases, les règles d'expression, les verdicts et les défis.",
      minutes: 9,
      topics: ["pipeline", "expressions", "verdicts", "défis"],
    },
    {
      slug: "api",
      icon: "code",
      title: "API",
      lead: "Points d'entrée REST pour l'automatisation, contrat gRPC des agents et authentification.",
      minutes: 7,
      topics: ["REST", "gRPC", "auth", "automatisation"],
    },
  ],
  sidebarLabel: "Documentation",
  screenshot: {
    key: "configVersions",
    url: "localhost:9080/config-versions",
    caption: "Chaque changement de politique est une version comparable et réversible.",
    alt: "Liste des versions de configuration avec différences et actions de restauration",
  },
  github: {
    title: "La documentation complète est dans le dépôt",
    body: "Guide de démarrage, manuel utilisateur, cycle de vie HTTP, détails ACME, benchmarks et politique de sécurité, versionnés avec le code.",
    link: { label: "Parcourir la documentation", path: "https://github.com/shuaiZend/PingWAF/tree/main/docs" },
  },
  backToHub: "Tous les documents",
  editLabel: "Modifier cette page sur GitHub",
};

export default docs;
