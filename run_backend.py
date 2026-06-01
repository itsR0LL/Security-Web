from __future__ import annotations

import os

import uvicorn


if __name__ == "__main__":
    host = os.environ.get("SECURITY_API_HOST", "127.0.0.1")
    port = int(os.environ.get("SECURITY_API_PORT", "8787"))
    uvicorn.run("security_core.main:app", host=host, port=port, reload=False)

