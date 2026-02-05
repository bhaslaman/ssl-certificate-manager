"""SSL Certificate Manager - FastAPI Application."""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import json
import os

from .routers import convert, analyze, generate

# Get the app directory
APP_DIR = Path(__file__).parent

app = FastAPI(
    title="SSL Certificate Manager",
    description="Web-based SSL certificate management tool",
    version="1.0.0"
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


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}
