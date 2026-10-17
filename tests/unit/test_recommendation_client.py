"""No network or credentials required for the Responses API adapter."""

import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from core.consulting.openai_client import (
    OpenAIRecommendationClient, RecommendationAPIError, RecommendationRefusedError,
)
from core.consulting.prompts import ACTION_OPTIONS

GOOD_ACTIONS = {key: [options[0]] for key, options in ACTION_OPTIONS.items()}


def response(content, status="completed"):
    return io.BytesIO(json.dumps({"status": status, "output": [
        {"type": "message", "content": content}]}).encode("utf-8"))


class RecommendationClientTests(unittest.TestCase):
    def setUp(self):
        self.client = OpenAIRecommendationClient(api_key="offline-key", model="offline-model", timeout=3)

    def test_strict_structured_outputs_request(self):
        def fake_urlopen(request, timeout):
            self.assertEqual(timeout, 3)
            body = json.loads(request.data)
            self.assertEqual(body["model"], "offline-model")
            self.assertFalse(body["store"])
            self.assertEqual(body["text"]["format"]["type"], "json_schema")
            self.assertTrue(body["text"]["format"]["strict"])
            self.assertFalse(body["text"]["format"]["schema"]["additionalProperties"])
            return response([{"type": "output_text", "text": json.dumps(GOOD_ACTIONS)}])
        with patch("core.consulting.openai_client.urlopen", fake_urlopen):
            self.assertEqual(self.client.generate({"cve": "CVE-2021-44228"}), GOOD_ACTIONS)

    def test_refusal_incomplete_and_bad_format(self):
        cases = [
            (response([{"type": "refusal", "refusal": "no"}]), RecommendationRefusedError),
            (response([{"type": "output_text", "text": "{}"}], "incomplete"), RecommendationAPIError),
            (response([{"type": "output_text", "text": "not-json"}]), RecommendationAPIError),
            (response([]), RecommendationAPIError),
        ]
        for document, error_type in cases:
            with self.subTest(error_type=error_type), patch(
                    "core.consulting.openai_client.urlopen", return_value=document):
                with self.assertRaises(error_type):
                    self.client.generate({})

    def test_http_transport_and_configuration_failures(self):
        for error in (HTTPError("url", 429, "rate limit", {}, None),
                      URLError("offline"), TimeoutError()):
            with self.subTest(error=type(error).__name__), patch(
                    "core.consulting.openai_client.urlopen", side_effect=error):
                with self.assertRaises(RecommendationAPIError):
                    self.client.generate({})
        with self.assertRaises(RecommendationAPIError):
            OpenAIRecommendationClient(api_key="", model="offline-model").generate({})
        with self.assertRaises(ValueError):
            OpenAIRecommendationClient(api_key="x", model="m", timeout=float("nan"))


if __name__ == "__main__":
    unittest.main()
