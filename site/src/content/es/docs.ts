import type { DocsContent } from "../schema";

const docs = {
  meta: {
    title: "Documentación — PingWAF",
    description:
      "Arquitectura, despliegue, motor WAF y API REST/gRPC: los cuatro documentos necesarios para operar PingWAF en producción.",
  },
  hero: {
    eyebrow: "Documentación",
    title: "Los cuatro documentos que explican PingWAF",
    lead: "Empieza por la arquitectura si estás evaluando, por el despliegue si vas a instalar y por el motor WAF si vas a ajustar reglas.",
  },
  cards: [
    {
      slug: "architecture",
      icon: "network",
      title: "Arquitectura",
      lead: "Cómo encajan el plano de control y el de datos, y qué transporta el protocolo gRPC.",
      minutes: 8,
      topics: ["plano de control", "plano de datos", "gRPC", "modos"],
    },
    {
      slug: "deployment",
      icon: "server",
      title: "Despliegue",
      lead: "All-in-one frente a distribuido, Docker y systemd, puertos y precedencia de configuración.",
      minutes: 10,
      topics: ["docker", "systemd", "puertos", "entorno"],
    },
    {
      slug: "waf-engine",
      icon: "shield",
      title: "Motor WAF",
      lead: "El pipeline de cuatro fases, reglas de expresión, veredictos y flujo de desafíos.",
      minutes: 9,
      topics: ["pipeline", "expresiones", "veredictos", "desafíos"],
    },
    {
      slug: "api",
      icon: "code",
      title: "API",
      lead: "Endpoints REST para automatización, contrato gRPC para agentes y autenticación.",
      minutes: 7,
      topics: ["REST", "gRPC", "auth", "automatización"],
    },
  ],
  sidebarLabel: "Documentación",
  screenshot: {
    key: "configVersions",
    url: "localhost:9080/config-versions",
    caption: "Cada cambio de política es una versión que puedes comparar y revertir.",
    alt: "Lista de versiones de configuración con diferencias y acciones de rollback",
  },
  github: {
    title: "La documentación completa está en el repositorio",
    body: "Guía de inicio, manual de usuario, ciclo de vida HTTP, detalles de ACME, benchmarks y política de seguridad, versionados junto al código.",
    link: { label: "Ver documentación en GitHub", path: "https://github.com/shuaiZend/PingWAF/tree/main/docs" },
  },
  backToHub: "Todos los documentos",
  editLabel: "Editar esta página en GitHub",
};

export default docs;
