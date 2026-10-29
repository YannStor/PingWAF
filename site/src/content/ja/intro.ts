import type { IntroContent } from "../schema";

const intro = {
  meta: {
    title: "PingWAF — Pingora ベースの分散型 Web アプリケーションファイアウォール",
    description:
      "pingap と Cloudflare Pingora を基盤としたオープンソース WAF。単一のコントロールプレーン、複数のエッジエージェント、意味解析による検知、CC・ボット対策、自動 TLS、組み込みコンソール。",
  },
  hero: {
    badges: ["Apache-2.0", "Rust · Pingora", "セルフホスト"],
    title: "Cloudflare クラスの防御を",
    titleAccent: "自分のインフラに",
    lead: "PingWAF は分散型で集中管理される Web アプリケーションファイアウォールです。サイト・ルール・ポリシーをコントロールプレーンで一度定義すれば、各エッジエージェントが数秒で適用します。リロードもダウンタイムも不要です。",
    primary: { label: "5 分で開始", path: "/quickstart/" },
    secondary: { label: "ドキュメントを読む", path: "/docs/" },
    stats: [
      { value: "4 フェーズ", label: "正規化 → シグネチャ → 式 → スコア" },
      { value: "7 RPC", label: "コントロールプレーンの gRPC プロトコル" },
      { value: "5 プロバイダ", label: "DNS-01 ACME 連携" },
    ],
    pills: [
      { icon: "shield-check", text: "SQLi · XSS · RCE · パストラバーサル" },
      { icon: "refresh", text: "ルールは数秒で反映" },
    ],
    shot: {
      key: "dashboard",
      url: "localhost:9080/dashboard",
      caption: "組み込みコンソールでトラフィック・攻撃・エージェントの状態を確認。",
      alt: "PingWAF のダッシュボード。リクエスト分析、攻撃傾向、エージェント状態を表示",
    },
  },
  proof: [
    {
      value: "Apache-2.0",
      label: "エンドツーエンドでオープンソース",
      note: "リクエスト課金もホスト型サービスへの依存もありません。",
    },
    {
      value: "Rust",
      label: "メモリ安全なデータプレーン",
      note: "Pingora と tokio を 1 つの自己完結バイナリに。",
    },
    {
      value: "PostgreSQL",
      label: "コントロールプレーンの状態",
      note: "サイト、ルール、設定スナップショット、監査履歴。",
    },
    {
      value: "gRPC",
      label: "ルールのホット同期",
      note: "双方向ストリーム。プロセスの再起動は不要。",
    },
  ],
  architecture: {
    eyebrow: "アーキテクチャ",
    title: "1 つのコントロールプレーン、多数のエッジエージェント",
    lead: "コントロールプレーンが設定の唯一の正解です。エージェントはトラフィックとポリシー適用だけを担うため、状態に触れずにデータプレーンを拡張できます。",
    points: [
      {
        title: "状態はコントロールプレーンが保持",
        body: "サイト、ルール、証明書、設定バージョンは PostgreSQL に保存され、Axum の REST API、tonic の gRPC、組み込みコンソールから操作します。",
      },
      {
        title: "エージェントがエッジで適用",
        body: "各エージェントはディスク上のルールキャッシュを保持し、コントロールプレーンに到達できなくても最後に同期したポリシーで提供を続けます。",
      },
      {
        title: "リロードなしで変更が届く",
        body: "SyncRules が既存の双方向ストリームで新しい設定を送信し、エージェントはリクエストを流したままメモリ上で差し替えます。",
      },
    ],
    diagram: {
      lanes: [
        {
          label: "クライアント",
          nodes: [{ title: "ブラウザ / API クライアント", meta: "HTTPS" }],
        },
        {
          label: "データプレーン · エージェント",
          nodes: [
            { title: "エッジエージェント A", meta: ":80 / :443", accent: true },
            { title: "エッジエージェント B", meta: ":80 / :443", accent: true },
          ],
        },
        {
          label: "コントロールプレーン · サーバ",
          nodes: [
            { title: "REST + コンソール", meta: ":9080" },
            { title: "gRPC コントロールプレーン", meta: ":9090" },
            { title: "PostgreSQL", meta: "SeaORM" },
            { title: "Elasticsearch", meta: "任意" },
          ],
        },
        {
          label: "オリジン",
          nodes: [{ title: "アップストリームプール", meta: "HTTP / HTTPS" }],
        },
      ],
      links: [
        "HTTP / HTTPS",
        "gRPC 双方向ストリーム · Heartbeat · ShipLogs · SyncRules",
        "プロキシされたリクエスト",
      ],
    },
    link: { label: "コントロールプレーンの仕組み", path: "/docs/architecture/" },
  },
  capabilities: {
    eyebrow: "機能",
    title: "多層防御を、既定ではすべて無効で",
    lead: "すべての防御は無効な状態で提供され、サイト単位で有効化します。有効にするまでトラフィックの挙動は変わりません。",
    items: [
      {
        icon: "shield",
        title: "意味解析 WAF エンジン",
        body: "SQL インジェクション、XSS、RCE、パストラバーサル、コマンドインジェクションをシグネチャとヒューリスティックで検知します。",
        points: [
          "libinjection と Aho-Corasick の併用",
          "Cloudflare 風の式ルール",
          "Pass / Monitor / Block / Challenge の判定",
        ],
        link: { label: "WAF エンジン", path: "/features/#waf-engine" },
      },
      {
        icon: "bot",
        title: "CC・ボット対策",
        body: "段階的なチャレンジで急増するリクエストを吸収し、実際のブラウザとスクリプトを切り分けます。",
        points: [
          "JavaScript 5 秒シールドと Proof of Work",
          "HMAC 署名付きクリアランス Cookie",
          "サイト単位の検証済みボット許可リスト",
        ],
        link: { label: "CC・ボット対策", path: "/features/#cc-bot" },
      },
      {
        icon: "key",
        title: "アクセス制御",
        body: "アドレス、地域、リクエストの観点でオリジンへ到達できる相手を決めます。",
        points: [
          "CIDR と CSV インポートに対応した IP ルール",
          "国と ASN による地域制限",
          "IP・ホスト・パス・ヘッダー単位のレート制限",
        ],
        link: { label: "アクセス制御", path: "/features/#access-control" },
      },
      {
        icon: "route",
        title: "トラフィックとキャッシュ",
        body: "コンソールから離れずにルーティング、負荷分散、キャッシュを設定できます。",
        points: [
          "5 種類の負荷分散を備えたオリジンプール",
          "プレフィックス・完全一致・正規表現のルート",
          "クォータと SWR を備えたエッジキャッシュ",
        ],
        link: { label: "トラフィックとキャッシュ", path: "/features/#traffic-caching" },
      },
      {
        icon: "lock",
        title: "TLS と証明書",
        body: "証明書はエッジで発行され、状態は 1 か所で確認できます。",
        points: [
          "ACME HTTP-01 / DNS-01 と自動更新",
          "ハートビートによるサイト別証明書状態",
          "mTLS の発行と即時失効",
        ],
        link: { label: "TLS と証明書", path: "/features/#tls" },
      },
      {
        icon: "activity",
        title: "可観測性とコンソール",
        body: "すべてのリクエストを監査でき、すべての設定変更を元に戻せます。",
        points: [
          "WAL バッファ付きで Elasticsearch へログ出力",
          "再現可能なリクエスト／レスポンスの生データ保存",
          "差分とロールバックを備えた設定バージョン",
        ],
        link: { label: "可観測性", path: "/features/#observability" },
      },
    ],
    link: { label: "すべての機能", path: "/features/" },
  },
  showcase: {
    eyebrow: "コンソールの中身",
    title: "別のスタックなしで運用",
    lead: "コンソールはバイナリに埋め込まれているため、画面に見えているものがそのままコントロールプレーンの事実です。",
    shots: [
      {
        key: "waf",
        url: "localhost:9080/sites/example.com/security/protection",
        caption: "WAF ルールと CC チャレンジはサイト単位で設定します。",
        alt: "WAF ルールのタブとチャレンジ設定を表示するサイト保護ページ",
      },
      {
        key: "logs",
        url: "localhost:9080/logs",
        caption: "リクエストログには判定・スコア・一致ルールが残ります。",
        alt: "判定と一致ルールを表示するリクエストログ一覧",
      },
      {
        key: "ssl",
        url: "localhost:9080/sites/example.com/ssl",
        caption: "サイトごとの証明書状態と ACME イベント。",
        alt: "証明書状態と ACME イベントを表示するサイト TLS ページ",
      },
    ],
  },
  quickstart: {
    eyebrow: "クイックスタート",
    title: "ゼロから保護されたサイトまで",
    lead: "同梱の compose ファイルがコントロールプレーン、エージェント、PostgreSQL をまとめて起動します。ログインしてサイトを追加すれば、エッジが適用を開始します。",
    steps: [
      { title: "スタックを起動", body: "docker compose up -d で公開イメージと PostgreSQL を起動します。" },
      { title: "ログイン", body: "https://localhost:9080 を開き、初期管理者アカウントでログインします。" },
      { title: "サイトを追加", body: "ドメインをエージェントに向け、サイト単位で防御を有効にします。" },
    ],
    terminal: {
      title: "bash — pingwaf",
      lines: [
        "$ git clone https://github.com/shuaiZend/PingWAF.git",
        "$ cd PingWAF && docker compose up -d",
        "コントロールプレーン  https://localhost:9080",
        "エージェント          :80 / :443",
        "postgres              :5432",
      ],
    },
    primary: { label: "クイックスタート全文", path: "/quickstart/" },
    secondary: { label: "デプロイガイド", path: "/docs/deployment/" },
  },
  cta: {
    title: "読み、監査し、所有できる WAF",
    lead: "ルールも判定もログも、すべて自分のインフラに残ります。ライセンスはそのすべてを変更することを許します。",
    primary: { label: "はじめる", path: "/quickstart/" },
    secondary: { label: "GitHub でスター", path: "https://github.com/shuaiZend/PingWAF" },
  },
} satisfies IntroContent;

export default intro;
