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
const requestUrl = new URL(context.request.url);
const requestCf = context.request.cf || {};
const requestHeaders = context.request.headers;

context.waitUntil(
  fetch(`${context.env.SECURITY_LOG_COLLECTOR_URL}/collect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${context.env.SECURITY_LOG_INGEST_TOKEN}`,
    },
    body: JSON.stringify({
      occurredAt: new Date().toISOString(),
      clientIp: requestHeaders.get("CF-Connecting-IP") || "",
      country: requestHeaders.get("CF-IPCountry") || requestCf.country || "",
      region: requestHeaders.get("CF-Region") || requestCf.region || "",
      regionCode: requestHeaders.get("CF-Region-Code") || requestCf.regionCode || "",
      city: requestHeaders.get("CF-IPCity") || requestCf.city || "",
      latitude: requestHeaders.get("CF-IPLatitude") || requestCf.latitude || "",
      longitude: requestHeaders.get("CF-IPLongitude") || requestCf.longitude || "",
      postalCode: requestHeaders.get("CF-Postal-Code") || requestCf.postalCode || "",
      timezone: requestHeaders.get("CF-Timezone") || requestCf.timezone || "",
      colo: requestCf.colo || "",
      asn: requestCf.asn || "",
      asOrganization: requestCf.asOrganization || "",
      method: context.request.method,
      host: requestUrl.host,
      path: requestUrl.pathname,
      query: requestUrl.search.replace(/^\?/, ""),
      statusCode: response.status,
      userAgent: requestHeaders.get("User-Agent") || "",
      referer: requestHeaders.get("Referer") || "",
      source: "personal-blog",
    }),
  })
);
```

不要在前端浏览器里直接调用 `/collect`，否则密钥会暴露。没有显式传入这些原始访问者字段时，日志 Worker 只能读取采集请求本身的 Cloudflare 元数据，来源国家、城市和经纬度会失真。

## 本地 IP2Location LITE DB11 回填

项目支持用 IP2Location LITE DB11 IPv4/IPv6 的官方 CSV 或 ZIP 文件做本地离线 GeoIP 查询。该路径不会把访问 IP 发给第三方 API。

需要的文件名：

- `IP2LOCATION-LITE-DB11.CSV` 或 `IP2LOCATION-LITE-DB11.CSV.ZIP`
- `IP2LOCATION-LITE-DB11.IPV6.CSV` 或 `IP2LOCATION-LITE-DB11.IPV6.CSV.ZIP`

默认放置目录：

```powershell
Security Studio\security_data\ip2location\
```

预览导入：

```powershell
python scripts/import_ip2location_lite.py
```

导入并回填本地 SQLite：

```powershell
python scripts/import_ip2location_lite.py --apply
```

脚本会先备份 `security_data/security_studio.sqlite3`，然后导入 `ip2location_ranges`，再回填 `access_logs` 与 `raw_events` 中的国家、地区、城市、经纬度和定位精度。DB11 不包含 ASN 字段；ASN 仍来自 Cloudflare 日志字段，如需 ASN 离线补全，需要再接入 IP2Location ASN 版本。
