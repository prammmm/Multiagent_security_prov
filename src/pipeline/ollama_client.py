"""Minimal, robust HTTP client for local Ollama inference."""

import json
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional


class OllamaClient:
    """Client for querying local Ollama instance with deterministic parameters."""

    def __init__(self, base_url: str = "http://127.0.0.1:11434", default_model: str = "qwen2.5:3b"):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 512,
        num_ctx: int = 2048,
        format_json: bool = False,
    ) -> Dict[str, Any]:
        """Perform a single non-streaming generation request."""
        target_model = model or self.default_model
        endpoint = f"{self.base_url}/api/generate"

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "num_ctx": num_ctx,
            },
        }

        if system_prompt:
            payload["system"] = system_prompt

        if format_json:
            payload["format"] = "json"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        start_time = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                res_body = response.read().decode("utf-8")
                parsed = json.loads(res_body)
                elapsed = time.perf_counter() - start_time
                parsed["client_duration_seconds"] = elapsed
                return parsed
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to communicate with Ollama at {endpoint}: {e}") from e
