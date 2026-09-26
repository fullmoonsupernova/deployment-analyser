#!/usr/bin/env python3
import os
import uvicorn
from backend.app.config import settings

if __name__ == "__main__":
    is_dev = settings.APP_ENV == "development" and os.getenv("RELOAD", "false").lower() == "true"
    print(f"🚀 Starting SRE Production Deployment Risk Analyzer on http://{settings.HOST}:{settings.PORT}")
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=is_dev)
