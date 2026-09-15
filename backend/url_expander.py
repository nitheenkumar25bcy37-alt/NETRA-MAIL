"""Opt-in URL expansion through the constrained inspection worker."""
import os
from backend.inspection_client import inspect_task


class URLExpander:
    @staticmethod
    def expand(url, timeout=3.0, max_redirects=5):
        original = str(url or "")
        fallback = {"original_url": original, "final_url": original,
            "redirect_chain": [], "expanded": False}
        if os.getenv("NETRA_EXPAND_SHORT_URLS", "0").lower() not in {"1", "true", "yes"}:
            return {**fallback, "error": "isolated_fetch_disabled"}
        result = inspect_task({"operation": "url", "url": original})
        if not result.get("available"):
            return {**fallback, "error": result.get("error", "isolated_fetch_unavailable")}
        return {**fallback, **result}
