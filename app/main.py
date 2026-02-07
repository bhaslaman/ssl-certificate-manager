"""SSL Certificate Manager - FastAPI Application."""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import json
import os
import httpx

from .routers import convert, analyze, generate, check

# Get the app directory
APP_DIR = Path(__file__).parent

CURRENT_VERSION = "2.0.0"
GITHUB_REPO = "bhaslaman/ssl-certificate-manager"

app = FastAPI(
    title="SSL Certificate Manager",
    description="Web-based SSL certificate management tool",
    version=CURRENT_VERSION
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

# Templates
templates = Jinja2Templates(directory=APP_DIR / "templates")

# Load i18n translations
translations = {}
i18n_dir = APP_DIR / "i18n"
for lang_file in i18n_dir.glob("*.json"):
    lang_code = lang_file.stem
    with open(lang_file, "r", encoding="utf-8") as f:
        translations[lang_code] = json.load(f)


def get_translation(lang: str = "tr") -> dict:
    """Get translations for a language."""
    return translations.get(lang, translations.get("en", {}))


# Include routers
app.include_router(convert.router)
app.include_router(analyze.router)
app.include_router(generate.router)
app.include_router(check.router)


@app.get("/")
async def index(request: Request, lang: str = "tr"):
    """Render the main page."""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "t": get_translation(lang),
            "lang": lang
        }
    )


@app.get("/convert")
async def convert_page(request: Request, lang: str = "tr"):
    """Render the convert page."""
    return templates.TemplateResponse(
        "convert.html",
        {
            "request": request,
            "t": get_translation(lang),
            "lang": lang
        }
    )


@app.get("/analyze")
async def analyze_page(request: Request, lang: str = "tr"):
    """Render the analyze page."""
    return templates.TemplateResponse(
        "analyze.html",
        {
            "request": request,
            "t": get_translation(lang),
            "lang": lang
        }
    )


@app.get("/generate")
async def generate_page(request: Request, lang: str = "tr"):
    """Render the generate page."""
    return templates.TemplateResponse(
        "generate.html",
        {
            "request": request,
            "t": get_translation(lang),
            "lang": lang
        }
    )


@app.get("/api/translations/{lang}")
async def get_translations(lang: str):
    """Get translations for a specific language."""
    return get_translation(lang)


@app.get("/check")
async def check_page(request: Request, lang: str = "tr"):
    """Render the SSL check page."""
    return templates.TemplateResponse(
        "check.html",
        {
            "request": request,
            "t": get_translation(lang),
            "lang": lang
        }
    )


@app.get("/lifecycle")
async def lifecycle_page(request: Request, lang: str = "tr"):
    """Render the SSL lifecycle page."""
    return templates.TemplateResponse(
        "lifecycle.html",
        {
            "request": request,
            "t": get_translation(lang),
            "lang": lang
        }
    )


@app.get("/docs-page")
async def docs_page(request: Request, lang: str = "tr"):
    """Render the documentation page."""
    return templates.TemplateResponse(
        "docs.html",
        {
            "request": request,
            "t": get_translation(lang),
            "lang": lang
        }
    )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": CURRENT_VERSION}


@app.get("/api/system/update-check")
async def check_update():
    """
    Check for available updates from GitHub releases.

    Returns current version, latest version, and update availability.
    """
    result = {
        "current_version": CURRENT_VERSION,
        "latest_version": None,
        "update_available": False,
        "release_url": None,
        "error": None
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                headers={"Accept": "application/vnd.github.v3+json"}
            )

            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("tag_name", "").lstrip("v")
                result["latest_version"] = latest_version
                result["release_url"] = data.get("html_url")

                # Compare versions
                if latest_version and latest_version != CURRENT_VERSION:
                    # Simple version comparison (semver)
                    try:
                        current_parts = [int(x) for x in CURRENT_VERSION.split(".")]
                        latest_parts = [int(x) for x in latest_version.split(".")]
                        result["update_available"] = latest_parts > current_parts
                    except ValueError:
                        result["update_available"] = latest_version != CURRENT_VERSION
            elif response.status_code == 404:
                result["error"] = "Repository not found or no releases"
            else:
                result["error"] = f"GitHub API returned status {response.status_code}"

    except httpx.TimeoutException:
        result["error"] = "Request timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


@app.get("/api/system/version")
async def get_version():
    """Get current application version."""
    return {"version": CURRENT_VERSION}
