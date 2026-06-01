# Security Studio Backend

FastAPI 后端位于 `security_core`，本地 SQLite 数据默认写入 `security_data/security_studio.sqlite3`。

## 启动

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python run_backend.py
```

默认地址：

```text
http://127.0.0.1:8787
```

前端可配置：

```powershell
$env:NEXT_PUBLIC_SECURITY_API_BASE_URL="http://127.0.0.1:8787"
```

## 已实现接口

- `GET /api/health`
- `GET /api/overview`
- `GET /api/events`
- `GET /api/events/{id}`
- `GET /api/aggregates/trends`
- `GET /api/aggregates/sources`
- `GET /api/aggregates/map`
- `GET /api/sync/status`
- `POST /api/sync/run`
- `GET /api/settings`
- `POST /api/settings/cloudflare`
- `POST /api/token/check`
- `POST /api/settings/risk-threshold`
- `GET /api/rules`

无 Cloudflare Token 时，启动阶段会自动初始化 SQLite 并写入样例事件与聚合数据。配置 Token 后，`/api/token/check` 只执行本地结构校验，不调用 Cloudflare。

