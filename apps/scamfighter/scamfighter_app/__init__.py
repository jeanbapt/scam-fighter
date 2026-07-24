"""ScamFighter application layer (CLI wiring over scamfighter_core)."""

from scamfighter_app.cli import build_router, main, run_ingest

__all__ = ["build_router", "main", "run_ingest"]
