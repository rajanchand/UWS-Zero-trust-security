"""ZTS - Zero Trust Security Demo application."""

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.routes.auth import router as auth_router
from app.routes.dashboard import router as dash_router

app = FastAPI(
    title="ZTS - Zero Trust Security Demo",
    description="MSc Dissertation - NIST SP 800-207 based Zero Trust Architecture",
    version="1.0.0",
)

# static files
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# register route modules
app.include_router(auth_router)
app.include_router(dash_router)


@app.get("/")
async def root():
    return RedirectResponse("/login")


@app.get("/health")
async def health():
    return {"status": "ok", "app": "ZTS"}
