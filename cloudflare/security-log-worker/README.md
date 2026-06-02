# Security Log Worker

这个 Worker 用于在 Cloudflare 侧暂存博客访问日志，解决源站只有 IPv6、无法被普通 IPv4 环境直接访问的问题。

## 接口

- `POST /collect`：写入访问摘要，需要 `INGEST_TOKEN`。
- `GET /export?cursor=0&limit=500`：导出访问摘要，需要 `EXPORT_TOKEN`。
- `GET /health`：查看 Worker 与 D1 是否可用。

## Cloudflare 侧配置

```powershell
cd cloudflare/security-log-worker
npm install
npx wrangler login
npx wrangler d1 create security_studio_logs
```

把 `wrangler d1 create` 输出的 `database_id` 写入 `wrangler.toml`：

```toml
[[d1_databases]]
binding = "SECURITY_LOG_DB"
database_name = "security_studio_logs"
database_id = "Cloudflare 输出的 database_id"
```

初始化 D1 表：

```powershell
npx wrangler d1 execute security_studio_logs --remote --file=./schema.sql
```

设置两个密钥：

```powershell
npx wrangler secret put INGEST_TOKEN
npx wrangler secret put EXPORT_TOKEN
```

部署：

```powershell
npx wrangler deploy
```

## Security Studio 后端配置

部署后把导出地址和导出密钥配置给后端：

```powershell
$env:SECURITY_WORKER_LOG_EXPORT_URL="https://你的 Worker 域名/export"
$env:SECURITY_WORKER_LOG_EXPORT_TOKEN="你的 EXPORT_TOKEN"
```

然后启动后端并执行：

```powershell
Invoke-RestMethod -Method POST http://127.0.0.1:8787/api/worker-logs/sync
```

## 博客侧采集方式

博客 Pages Function 或 Worker 在请求完成后，向 `/collect` 发送访问摘要：

```js
context.waitUntil(
  fetch(`${context.env.SECURITY_LOG_COLLECTOR_URL}/collect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${context.env.SECURITY_LOG_INGEST_TOKEN}`,
    },
    body: JSON.stringify({
      occurredAt: new Date().toISOString(),
      method: context.request.method,
      host: new URL(context.request.url).host,
      path: new URL(context.request.url).pathname,
      query: new URL(context.request.url).search.replace(/^\?/, ""),
      statusCode: response.status,
      userAgent: context.request.headers.get("User-Agent") || "",
      referer: context.request.headers.get("Referer") || "",
      source: "personal-blog",
    }),
  })
);
```

不要在前端浏览器里直接调用 `/collect`，否则密钥会暴露。
