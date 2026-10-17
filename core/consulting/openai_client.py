"""Small isolated OpenAI Responses API client using the standard library."""

from __future__ import annotations

import json
import math
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from core.consulting.prompts import ACTION_SCHEMA, SYSTEM_PROMPT, recommendation_prompt


class RecommendationAPIError(RuntimeError):
    pass


class RecommendationRefusedError(RecommendationAPIError):
    pass


class OpenAIRecommendationClient:
    def __init__(self, *, api_key: str | None = None, model: str | None = None,
                 timeout: float | None = None) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY", "")
        self.model = model if model is not None else os.getenv("OPENAI_RECOMMENDATION_MODEL", "")
        raw_timeout = timeout if timeout is not None else os.getenv("OPENAI_TIMEOUT_SECONDS", "30")
        try:
            self.timeout = float(raw_timeout)
        except (TypeError, ValueError) as exc:
            raise ValueError("OPENAI_TIMEOUT_SECONDS must be a positive number") from exc
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("OPENAI_TIMEOUT_SECONDS must be a positive number")

    def generate(self, input_data: dict) -> dict:
        if not self.api_key or not self.model:
            raise RecommendationAPIError("OpenAI key and recommendation model are required")
        payload = {
            "model": self.model,
            "store": False,
            "instructions": SYSTEM_PROMPT,
            "input": recommendation_prompt(input_data),
            "text": {"format": {"type": "json_schema", "name": "recommendation_actions",
                                "strict": True, "schema": ACTION_SCHEMA}},
        }
        request = Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                document = json.load(response)
        except HTTPError as exc:
            raise RecommendationAPIError(f"OpenAI HTTP error: {exc.code}") from exc
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            raise RecommendationAPIError("OpenAI request or response failed") from exc
        if not isinstance(document, dict) or document.get("status") != "completed":
            raise RecommendationAPIError("OpenAI response incomplete or invalid")
        output = document.get("output")
        if not isinstance(output, list):
            raise RecommendationAPIError("OpenAI output items are invalid")
        content = [part for item in output
                   if isinstance(item, dict) and item.get("type") == "message"
                   for part in (item.get("content") if isinstance(item.get("content"), list)
                                else []) if isinstance(part, dict)]
        if any(part.get("type") == "refusal" for part in content):
            raise RecommendationRefusedError("OpenAI refused the recommendation request")
        texts = [part.get("text") for part in content if part.get("type") == "output_text"]
        if len(texts) != 1 or not isinstance(texts[0], str):
            raise RecommendationAPIError("OpenAI structured output missing")
        try:
            parsed = json.loads(texts[0])
        except ValueError as exc:
            raise RecommendationAPIError("OpenAI structured output is not JSON") from exc
        if not isinstance(parsed, dict):
            raise RecommendationAPIError("OpenAI structured output is not an object")
        return parsed
