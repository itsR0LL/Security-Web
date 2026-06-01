# Security Studio

Security Studio 是一个面向个人博客后台的安全态势可视化与事件管理项目。

当前阶段目标是先完成可独立运行的 MVP：

- `/security`：安全态势首页，保留主视觉、数据状态、核心入口和最近高风险事件入口。
- `/security/events`：事件筛选、事件列表、事件详情与待发送告警文本。
- `/security/settings`：Cloudflare Zone / Token 配置、同步周期、高风险阈值和数据保留策略。
- `/security/situation`：安全态势仿真页，后续继续迭代 3D/2D 可视化能力。

## 技术栈

- Next.js / React / TypeScript
- Three.js
- FastAPI
- SQLite

## 本地启动

安装前端依赖：

```powershell
npm install
```

启动后端：

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python run_backend.py
```

启动前端并接入本地后端：

```powershell
$env:NEXT_PUBLIC_SECURITY_API_BASE_URL="http://127.0.0.1:8787"
npm run dev
```

前端默认地址：

```text
http://localhost:3000/security
```

后端默认地址：

```text
http://127.0.0.1:8787
```

## 数据与安全边界

- 未配置 Cloudflare Token 时，后端会自动使用样例数据。
- 当前 Cloudflare Token 检测仍处于 MVP 阶段，只做本地结构校验，不调用 Cloudflare。
- SQLite 数据库、运行日志、Playwright 检查记录、截图、环境变量和本地 skill 缓存不会提交到仓库。
- Token 不应写入源码或文档，只能通过本地配置接口保存到本地运行环境。

更多后端接口说明见 [README_BACKEND.md](README_BACKEND.md)。
