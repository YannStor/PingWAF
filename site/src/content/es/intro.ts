import type { IntroContent } from "../schema";

const intro = {
  meta: {
    title: "PingWAF — Firewall de aplicaciones web distribuido sobre Pingora",
    description:
      "WAF de código abierto sobre pingap y Cloudflare Pingora: un plano de control, muchos agentes en el edge, detección semántica, defensa CC y de bots, TLS automático y consola integrada.",
  },
  hero: {
    badges: ["Apache-2.0", "Rust · Pingora", "Autoalojado"],
    title: "Protección de nivel Cloudflare para",
    titleAccent: "infraestructura que tú controlas",
    lead: "PingWAF es un firewall de aplicaciones web distribuido y gestionado de forma centralizada. Define sitios, reglas y políticas una vez en el plano de control; cada agente del edge las aplica en segundos, sin reinicios ni caídas.",
    primary: { label: "Empezar en 5 minutos", path: "/quickstart/" },
    secondary: { label: "Leer la documentación", path: "/docs/" },
    stats: [
      { value: "4 fases", label: "Normalizar → firmas → expresiones → puntuación" },
      { value: "7 RPC", label: "Protocolo gRPC del plano de control" },
      { value: "5 proveedores", label: "Integraciones ACME DNS-01" },
    ],
    pills: [
      { icon: "shield-check", text: "SQLi · XSS · RCE · traversal" },
      { icon: "refresh", text: "Reglas aplicadas en segundos" },
    ],
    shot: {
      key: "dashboard",
      url: "localhost:9080/dashboard",
      caption: "Tráfico, ataques y estado de los agentes en la consola integrada.",
      alt: "Panel de PingWAF con analítica de peticiones, tendencias de ataque y estado de agentes",
    },
  },
  proof: [
    {
      value: "Apache-2.0",
      label: "Código abierto de extremo a extremo",
      note: "Sin coste por petición y sin dependencia de un servicio alojado.",
    },
    {
      value: "Rust",
      label: "Plano de datos con memoria segura",
      note: "Pingora + tokio en un único binario autocontenido.",
    },
    {
      value: "PostgreSQL",
      label: "Estado del plano de control",
      note: "Sitios, reglas, instantáneas de configuración y auditoría.",
    },
    {
      value: "gRPC",
      label: "Sincronización en caliente",
      note: "Flujos bidireccionales, sin reiniciar procesos.",
    },
  ],
  architecture: {
    eyebrow: "Arquitectura",
    title: "Un plano de control, muchos agentes",
    lead: "El plano de control es la única fuente de verdad de la configuración. Los agentes solo transportan tráfico y aplican políticas, así que puedes escalar el plano de datos sin tocar el estado.",
    points: [
      {
        title: "El plano de control posee el estado",
        body: "Sitios, reglas, certificados y versiones de configuración viven en PostgreSQL, detrás de una API REST en Axum, un servicio gRPC en tonic y la consola integrada.",
      },
      {
        title: "Los agentes aplican en el edge",
        body: "Cada agente mantiene una caché de reglas en disco y sigue sirviendo con la última política conocida aunque el plano de control no esté disponible.",
      },
      {
        title: "Los cambios llegan sin recargar",
        body: "SyncRules empuja un nuevo paquete por el flujo bidireccional existente; el agente lo intercambia en memoria mientras el tráfico continúa.",
      },
    ],
    diagram: {
      lanes: [
        {
          label: "Clientes",
          nodes: [{ title: "Navegador / cliente API", meta: "HTTPS" }],
        },
        {
          label: "Plano de datos · agente",
          nodes: [
            { title: "Agente edge A", meta: ":80 / :443", accent: true },
            { title: "Agente edge B", meta: ":80 / :443", accent: true },
          ],
        },
        {
          label: "Plano de control · servidor",
          nodes: [
            { title: "REST + consola", meta: ":9080" },
            { title: "gRPC ControlPlane", meta: ":9090" },
            { title: "PostgreSQL", meta: "SeaORM" },
            { title: "Elasticsearch", meta: "opcional" },
          ],
        },
        {
          label: "Origen",
          nodes: [{ title: "Grupos de origen", meta: "HTTP / HTTPS" }],
        },
      ],
      links: [
        "HTTP / HTTPS",
        "Flujos gRPC · Heartbeat · ShipLogs · SyncRules",
        "peticiones proxificadas",
      ],
    },
    link: { label: "Cómo funciona el plano de control", path: "/docs/architecture/" },
  },
  capabilities: {
    eyebrow: "Capacidades",
    title: "Defensa en profundidad, desactivada por defecto",
    lead: "Todas las protecciones se entregan desactivadas y se habilitan por sitio, de modo que nada altera tu tráfico hasta que lo pidas.",
    items: [
      {
        icon: "shield",
        title: "Motor WAF semántico",
        body: "Detección por firmas y heurísticas de inyección SQL, XSS, RCE, traversal y ejecución de comandos.",
        points: [
          "Heurísticas libinjection + Aho-Corasick",
          "Reglas de expresión estilo Cloudflare",
          "Veredictos Pass / Monitor / Block / Challenge",
        ],
        link: { label: "Motor WAF", path: "/features/#waf-engine" },
      },
      {
        icon: "bot",
        title: "Defensa CC y de bots",
        body: "Absorbe picos y separa navegadores reales de scripts con desafíos en capas.",
        points: [
          "Escudo JavaScript de 5 segundos y proof of work",
          "Cookies de paso firmadas con HMAC",
          "Lista de bots verificados por sitio",
        ],
        link: { label: "CC y bots", path: "/features/#cc-bot" },
      },
      {
        icon: "key",
        title: "Control de acceso",
        body: "Decide quién alcanza el origen por dirección, región y dimensión de la petición.",
        points: [
          "Reglas IP con CIDR e importación CSV",
          "Bloqueo geográfico por país y ASN",
          "Límites por IP, host, ruta o cabecera",
        ],
        link: { label: "Control de acceso", path: "/features/#access-control" },
      },
      {
        icon: "route",
        title: "Tráfico y caché",
        body: "Enruta, balancea y cachea sin salir de la consola.",
        points: [
          "Grupos de origen con cinco estrategias",
          "Rutas por prefijo, exactas y regex",
          "Caché en el edge con cuotas y SWR",
        ],
        link: { label: "Tráfico y caché", path: "/features/#traffic-caching" },
      },
      {
        icon: "lock",
        title: "TLS y certificados",
        body: "Certificados emitidos en el edge y visibles desde un único lugar.",
        points: [
          "ACME HTTP-01 y DNS-01 con renovación",
          "Estado del certificado por sitio en el heartbeat",
          "Emisión y revocación inmediata de mTLS",
        ],
        link: { label: "TLS y certificados", path: "/features/#tls" },
      },
      {
        icon: "activity",
        title: "Observabilidad y consola",
        body: "Cada petición es auditable y cada cambio de configuración reversible.",
        points: [
          "Logs en Elasticsearch con búfer WAL",
          "Captura de petición y respuesta para reproducir",
          "Versiones de configuración con diff y rollback",
        ],
        link: { label: "Observabilidad", path: "/features/#observability" },
      },
    ],
    link: { label: "Todas las capacidades", path: "/features/" },
  },
  showcase: {
    eyebrow: "Dentro de la consola",
    title: "Operación sin una pila adicional",
    lead: "El panel se compila dentro del binario: lo que ves es exactamente lo que sabe el plano de control.",
    shots: [
      {
        key: "waf",
        url: "localhost:9080/sites/example.com/security/protection",
        caption: "Las reglas WAF y los desafíos CC se configuran por sitio.",
        alt: "Página de protección del sitio con pestañas de reglas WAF y ajustes de desafío",
      },
      {
        key: "logs",
        url: "localhost:9080/logs",
        caption: "Los logs de petición guardan veredicto, puntuación y regla aplicada.",
        alt: "Lista de logs de petición con veredictos y reglas coincidentes",
      },
      {
        key: "ssl",
        url: "localhost:9080/sites/example.com/ssl",
        caption: "Estado del certificado y eventos ACME de cada sitio.",
        alt: "Página TLS del sitio con estado del certificado y eventos ACME",
      },
    ],
  },
  quickstart: {
    eyebrow: "Inicio rápido",
    title: "De cero a un sitio protegido",
    lead: "El archivo compose incluido arranca el plano de control, un agente y PostgreSQL. Inicia sesión, añade un sitio y el edge empieza a aplicar políticas.",
    steps: [
      { title: "Arranca la pila", body: "docker compose up -d descarga la imagen publicada e inicia PostgreSQL." },
      { title: "Inicia sesión", body: "Abre https://localhost:9080 con la cuenta de administrador inicial." },
      { title: "Añade un sitio", body: "Apunta un dominio al agente y habilita las protecciones del sitio." },
    ],
    terminal: {
      title: "bash — pingwaf",
      lines: [
        "$ git clone https://github.com/shuaiZend/PingWAF.git",
        "$ cd PingWAF && docker compose up -d",
        "plano de control  https://localhost:9080",
        "agente            :80 / :443",
        "postgres          :5432",
      ],
    },
    primary: { label: "Inicio rápido completo", path: "/quickstart/" },
    secondary: { label: "Guía de despliegue", path: "/docs/deployment/" },
  },
  cta: {
    title: "Un WAF que puedes leer, auditar y poseer",
    lead: "Cada regla, veredicto y línea de log se queda en tu infraestructura, con una licencia que te permite cambiarlo todo.",
    primary: { label: "Empezar", path: "/quickstart/" },
    secondary: { label: "Estrella en GitHub", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies IntroContent;

export default intro;
