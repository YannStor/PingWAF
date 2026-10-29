import type { QuickStartContent } from "../schema";

const quickstart = {
  meta: {
    title: "Inicio rápido — PingWAF",
    description:
      "Ejecuta PingWAF con Docker Compose o compílalo desde el código, inicia sesión, añade tu primer sitio y empieza a aplicar reglas en el edge.",
  },
  hero: {
    eyebrow: "Inicio rápido",
    title: "En marcha en cinco minutos, protegido en diez",
    lead: "Dos caminos oficiales: la pila compose incluida para evaluar, o una compilación propia para producción.",
    badges: [
      { icon: "container", label: "Ruta A", value: "Docker Compose" },
      { icon: "code", label: "Ruta B", value: "Compilar" },
      { icon: "clock", label: "Tiempo", value: "~5 minutos" },
      { icon: "database", label: "Almacén", value: "PostgreSQL 14+" },
    ],
    toc: [
      { id: "prerequisites", label: "Requisitos" },
      { id: "docker", label: "Docker Compose" },
      { id: "source", label: "Desde código" },
      { id: "credentials", label: "Primer acceso" },
      { id: "next", label: "Siguientes pasos" },
      { id: "troubleshooting", label: "Problemas" },
    ],
  },
  prereq: {
    title: "Antes de empezar",
    lead: "La ruta compose solo necesita Docker. Compilar requiere Rust, Node y protoc.",
    items: [
      {
        label: "Docker",
        value: "Engine 24+ con Compose v2",
        note: "Arranca el plano de control, un agente y PostgreSQL.",
      },
      {
        label: "PostgreSQL",
        value: "14+ (16 recomendado)",
        note: "El plano de control guarda sitios, reglas y versiones.",
      },
      {
        label: "Puertos",
        value: "9080 · 9090 · 80 · 443",
        note: "9080 sirve la API y la consola; 9090 el plano gRPC.",
      },
      {
        label: "TLS",
        value: "Autofirmado en el primer arranque",
        note: "Sustitúyelo o confíalo antes de exponer la consola.",
      },
    ],
  },
  paths: {
    docker: {
      id: "docker",
      title: "Docker Compose",
      lead: "El compose arranca PingWAF en modo all-in-one junto a PostgreSQL con la imagen publicada.",
      steps: [
        {
          title: "Clona el repositorio",
          body: "El compose y el TOML de ejemplo están en la raíz del repositorio.",
          code: {
            lang: "bash",
            code: "git clone https://github.com/shuaiZend/PingWAF.git\ncd PingWAF",
          },
        },
        {
          title: "Arranca la pila",
          body: "Define JWT_SECRET y ADMIN_PASSWORD si el host es accesible desde fuera.",
          code: {
            lang: "bash",
            code: "export JWT_SECRET=\"$(openssl rand -hex 32)\"\nexport ADMIN_PASSWORD=\"$(openssl rand -hex 16)\"\ndocker compose up -d",
          },
        },
        {
          title: "Abre la consola",
          body: "La consola usa HTTPS con un certificado autofirmado del primer arranque; el navegador avisará hasta que lo confíes o subas el tuyo en Ajustes.",
          code: {
            lang: "bash",
            code: "curl --connect-timeout 2 --max-time 3 http://localhost:9080/healthz\n# {\"status\":\"ok\",\"database\":\"up\"}",
          },
        },
        {
          title: "Añade tu primer sitio",
          body: "Crea un sitio con el dominio que apuntarás al agente y habilita solo las protecciones que necesites.",
        },
      ],
      note: "Los binarios publicados son para Linux amd64/arm64; la imagen Docker cubre ambas arquitecturas.",
      shot: {
        key: "sites",
        url: "localhost:9080/sites",
        caption: "La lista de sitios es donde empieza la aplicación: una fila por dominio.",
        alt: "Lista de sitios en la consola con tráfico y estado de protección",
      },
    },
    source: {
      id: "source",
      title: "Compilar desde el código",
      lead: "Usa esta ruta cuando necesites una compilación propia o un binario auditable.",
      steps: [
        {
          title: "Instala el toolchain",
          body: "protoc es obligatorio: sin él el crate proto cae en marcadores de posición y los crates posteriores fallan.",
          code: {
            lang: "bash",
            code: "# macOS\nbrew install protobuf\n\n# Debian / Ubuntu\nsudo apt install protobuf-compiler cmake",
          },
        },
        {
          title: "Compila la consola",
          body: "La consola se embebe en el binario, así que debe compilarse primero.",
          code: {
            lang: "bash",
            code: "cd web && npm ci && npm run build && cd ..",
          },
        },
        {
          title: "Compila el binario",
          body: "El conjunto full incluye motor WAF, desafíos y automatización de certificados.",
          code: {
            lang: "bash",
            code: "cargo build --release --bin pingwaf --features full",
          },
        },
        {
          title: "Ejecuta all-in-one",
          body: "Apunta a una instancia PostgreSQL; el esquema se crea en el primer arranque.",
          code: {
            lang: "bash",
            code: "./target/release/pingwaf all-in-one \\\n  --db-url \"postgres://pingwaf:pingwaf@localhost:5432/pingwaf\"",
          },
        },
      ],
      note: "En Linux puedes omitir la compilación con install.sh (--mode all-in-one).",
      shot: {
        key: "agents",
        url: "localhost:9080/agents",
        caption: "Una compilación propia puede actuar como plano de control y luego enrolar agentes.",
        alt: "Página de agentes con los nodos edge enrolados y su heartbeat",
      },
    },
  },
  credentials: {
    title: "Primer acceso",
    lead: "El plano de control crea un administrador en el primer arranque y la consola exige cambiar la contraseña.",
    rows: [
      { label: "Consola", value: "https://localhost:9080" },
      { label: "Correo", value: "admin@pingwaf.local" },
      { label: "Contraseña", value: "pingwaf123" },
      { label: "Secreto JWT", value: "≥ 16 caracteres" },
    ],
    warning: {
      title: "Cambia los valores por defecto antes de exponer nada",
      body: "PINGWAF_JWT_SECRET y PINGWAF_ADMIN_PASSWORD tienen valores funcionales. Define ambos, pon PINGWAF_ALLOW_REGISTRATION=false y mantén 9080 en una red privada o VPN.",
    },
    shot: {
      key: "login",
      url: "localhost:9080/login",
      caption: "Accede con la cuenta de administrador inicial; luego puedes vincular passkeys.",
      alt: "Página de acceso de PingWAF con campos de correo y contraseña",
    },
  },
  next: {
    title: "Siguientes pasos",
    lead: "Cuando el plano de control responde, el resto es configuración.",
    cards: [
      {
        icon: "globe",
        title: "Crea un sitio",
        body: "Un sitio une un dominio con grupos de origen, rutas y las protecciones que actives.",
        link: { label: "Modelo de sitio", path: "/docs/architecture/" },
      },
      {
        icon: "network",
        title: "Conecta agentes",
        body: "Ejecuta pingwaf server en el nodo de control y pingwaf agent en cada nodo edge; se registran por gRPC :9090.",
        link: { label: "Despliegue distribuido", path: "/docs/deployment/" },
      },
      {
        icon: "shield-check",
        title: "Activa protecciones",
        body: "Habilita el motor WAF, el escudo CC o la política de bots por sitio: nada se aplica hasta que lo hagas.",
        link: { label: "Capacidades", path: "/features/" },
      },
      {
        icon: "activity",
        title: "Envía los logs",
        body: "Manda los logs a Elasticsearch y conserva las capturas en PostgreSQL para reproducir.",
        link: { label: "Observabilidad", path: "/features/#observability" },
      },
    ],
  },
  troubleshooting: {
    title: "Si algo no arranca",
    items: [
      {
        q: "La compilación falla en pingwaf-proto",
        a: "Falta protoc. Instala protobuf-compiler (o brew install protobuf) y recompila: sin él el crate usa marcadores de posición.",
      },
      {
        q: "El navegador rechaza el certificado",
        a: "La consola usa HTTPS con certificado autofirmado. Confía en el certificado descargado o sube el tuyo en Ajustes → HTTPS del plano de control; define PINGWAF_TLS_SANS con el hostname real.",
      },
      {
        q: "Un agente nunca aparece",
        a: "Comprueba que alcanza el plano gRPC en :9090 (PINGWAF_SERVER_URL) y que no hay firewall ni proxy TLS por medio.",
      },
      {
        q: "El puerto 443 no abre",
        a: "443 solo se abre tras emitir o subir un certificado; hasta entonces el agente sirve HTTP en el puerto 80.",
      },
    ],
  },
  cta: {
    title: "¿Necesitas la versión larga?",
    lead: "Los documentos de despliegue y arquitectura cubren systemd, topologías distribuidas, precedencia de configuración y todas las variables de entorno.",
    primary: { label: "Guía de despliegue", path: "/docs/deployment/" },
    secondary: { label: "GitHub", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies QuickStartContent;

export default quickstart;
