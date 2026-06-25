"""Experimental FastAPI application."""

from __future__ import annotations

from fastapi import FastAPI

from wizintel.api.routes import router
from wizintel.constants import APP_NAME, VERSION

app = FastAPI(
    title=f"{APP_NAME} API",
    version=VERSION,
    description=(
        "Experimental read-only WizIntel API scaffold. "
        "Scan triggering is intentionally absent in v1."
    ),
)
app.include_router(router)
