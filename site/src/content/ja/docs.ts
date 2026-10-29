import type { DocsContent } from "../schema";

const docs = {
  meta: {
    title: "ドキュメント — PingWAF",
    description:
      "アーキテクチャ、デプロイ、WAF エンジン、REST/gRPC API。PingWAF を本番運用するための 4 つのドキュメント。",
  },
  hero: {
    eyebrow: "ドキュメント",
    title: "PingWAF を理解する 4 つのドキュメント",
    lead: "評価ならアーキテクチャ、導入ならデプロイ、ルール調整なら WAF エンジンから読み始めてください。",
  },
  cards: [
    {
      slug: "architecture",
      icon: "network",
      title: "アーキテクチャ",
      lead: "コントロールプレーンとデータプレーンの関係、gRPC が運ぶもの。",
      minutes: 8,
      topics: ["コントロールプレーン", "データプレーン", "gRPC", "実行モード"],
    },
    {
      slug: "deployment",
      icon: "server",
      title: "デプロイ",
      lead: "all-in-one と分散構成、Docker と systemd、ポート、設定の優先順位。",
      minutes: 10,
      topics: ["Docker", "systemd", "ポート", "環境変数"],
    },
    {
      slug: "waf-engine",
      icon: "shield",
      title: "WAF エンジン",
      lead: "4 フェーズのパイプライン、式ルール、判定、チャレンジ。",
      minutes: 9,
      topics: ["パイプライン", "式", "判定", "チャレンジ"],
    },
    {
      slug: "api",
      icon: "code",
      title: "API",
      lead: "自動化向け REST、エージェント向け gRPC 契約、認証方式。",
      minutes: 7,
      topics: ["REST", "gRPC", "認証", "自動化"],
    },
  ],
  sidebarLabel: "ドキュメント",
  screenshot: {
    key: "configVersions",
    url: "localhost:9080/config-versions",
    caption: "ポリシーの変更はすべて差分比較とロールバックが可能なバージョンになります。",
    alt: "差分とロールバック操作を含む設定バージョン一覧",
  },
  github: {
    title: "完全なドキュメントはリポジトリにあります",
    body: "クイックスタート、ユーザーガイド、HTTP ライフサイクル、ACME の詳細、ベンチマーク、セキュリティポリシーをコードと同じ場所で管理しています。",
    link: { label: "GitHub でドキュメントを見る", path: "https://github.com/shuaiZend/PingWAF/tree/main/docs" },
  },
  backToHub: "すべてのドキュメント",
  editLabel: "GitHub でこのページを編集",
};

export default docs;
