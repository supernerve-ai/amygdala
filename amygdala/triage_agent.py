"""Foundation-Sec triage agent for evaluating alert severity."""

import json
import os
import logging
from dataclasses import dataclass
from typing import Optional

import httpx
import yaml

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    """Result of alert triage evaluation."""
    severity: int  # 1-10 scale
    threshold: int
    category: str
    summary: str
    recommended_action: str


class TriageParseError(Exception):
    """Raised when model response cannot be parsed into TriageResult."""
    pass


class TriageAgent:
    """Evaluates security alerts using Foundation-Sec model.

    Sends structured prompts to the LLM, parses JSON responses,
    and returns typed TriageResult objects.
    """

    def __init__(self):
        self.model_endpoint = os.getenv("MODEL_ENDPOINT", "http://localhost:11434")
        self.model_name = os.getenv("MODEL_NAME", "foundation-sec")
        self.threshold = int(os.getenv("TRIAGE_THRESHOLD", "5"))
        self.timeout = int(os.getenv("MODEL_TIMEOUT", "60"))
        self._load_prompt()

    def _load_prompt(self):
        """Load triage prompt template from YAML file."""
        prompt_path = os.path.join(
            os.path.dirname(__file__), "..", "prompts", "triage_prompt.yaml"
        )
        try:
            with open(prompt_path, "r") as f:
                self.prompt_config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning("Triage prompt not found, using defaults")
            self.prompt_config = {
                "system": "You are a security triage analyst. Respond in JSON.",
                "user_template": "Analyze this alert: {alert_data}",
            }

    async def evaluate(self, alert: dict) -> TriageResult:
        """Evaluate an alert and return triage result.

        Args:
            alert: Raw alert dictionary from Splunk

        Returns:
            TriageResult with severity, category, summary, and action

        Raises:
            TriageParseError: If model response cannot be parsed
        """
        prompt = self._build_prompt(alert)
        system_prompt = self.prompt_config.get("system", "")

        try:
            response_text = await self._call_model(system_prompt, prompt)
            return self._parse_response(response_text)
        except TriageParseError:
            raise
        except httpx.ConnectError as e:
            logger.error(f"Cannot reach model endpoint: {e}")
            return self._fallback_result(alert, str(e))
        except httpx.TimeoutException as e:
            logger.error(f"Model request timed out: {e}")
            return self._fallback_result(alert, str(e))
        except Exception as e:
            logger.error(f"Triage evaluation failed: {e}")
            return self._fallback_result(alert, str(e))

    async def _call_model(self, system_prompt: str, user_prompt: str) -> str:
        """Send prompt to Foundation-Sec model and get response.

        Supports both Ollama-style (/api/generate) and OpenAI-compatible
        (/v1/chat/completions) endpoints.
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Try Ollama-style first
            try:
                response = await client.post(
                    f"{self.model_endpoint}/api/generate",
                    json={
                        "model": self.model_name,
                        "system": system_prompt,
                        "prompt": user_prompt,
                        "stream": False,
                        "format": "json",
                    },
                )
                if response.status_code == 200:
                    result = response.json()
                    return result.get("response", "")
            except httpx.ConnectError:
                pass

            # Fallback to OpenAI-compatible endpoint
            response = await client.post(
                f"{self.model_endpoint}/v1/chat/completions",
                json={
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]

    def _build_prompt(self, alert: dict) -> str:
        """Build the triage prompt from template and alert data.

        Uses the user_template from the prompt YAML, falling back
        to a simple format if template interpolation fails.
        """
        user_template = self.prompt_config.get("user_template", "")

        if user_template:
            try:
                return user_template.format(
                    alert_id=alert.get("id", "unknown"),
                    source=alert.get("source", "unknown"),
                    timestamp=alert.get("_time", alert.get("timestamp", "unknown")),
                    event_type=alert.get("event_type", "unknown"),
                    src_ip=alert.get("src_ip", "unknown"),
                    dst_ip=alert.get("dst_ip", "unknown"),
                    description=alert.get("description", "No description"),
                    raw_data=json.dumps(alert.get("raw_data", {}), indent=2),
                )
            except (KeyError, ValueError) as e:
                logger.warning(f"Template interpolation failed: {e}, using fallback")

        # Fallback: dump the whole alert
        system = self.prompt_config.get("system", "")
        return f"{system}\n\nAlert Data:\n{json.dumps(alert, indent=2)}"

    def _parse_response(self, response_text: str) -> TriageResult:
        """Parse model response JSON into structured TriageResult.

        Handles various response formats and validates fields.
        """
        if not response_text.strip():
            raise TriageParseError("Empty response from model")

        # Try to extract JSON from response (model might include extra text)
        json_str = self._extract_json(response_text)

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise TriageParseError(f"Invalid JSON in model response: {e}")

        # Validate and extract fields with defaults
        severity = data.get("severity")
        if severity is None:
            raise TriageParseError("Missing 'severity' field in model response")

        # Clamp severity to valid range
        severity = max(1, min(10, int(severity)))

        return TriageResult(
            severity=severity,
            threshold=self.threshold,
            category=data.get("category", "unknown"),
            summary=data.get("summary", "No summary provided")[:500],
            recommended_action=data.get("recommended_action", "Review manually")[:500],
        )

    def _extract_json(self, text: str) -> str:
        """Extract JSON object from text that might contain markdown or extra content."""
        text = text.strip()

        # If the whole thing is JSON, return it
        if text.startswith("{"):
            # Find matching closing brace
            depth = 0
            for i, char in enumerate(text):
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return text[: i + 1]
            return text

        # Look for JSON in code blocks
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            return text[start:end].strip()

        if "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start)
            return text[start:end].strip()

        # Look for first { to last }
        if "{" in text and "}" in text:
            start = text.index("{")
            end = text.rindex("}") + 1
            return text[start:end]

        return text

    def _fallback_result(self, alert: dict, error_msg: str) -> TriageResult:
        """Generate a fallback result when the model is unavailable.

        Uses heuristics from the alert data to estimate severity.
        """
        severity_hint = alert.get("severity_hint", "medium")
        hint_map = {"low": 3, "medium": 5, "high": 7, "critical": 9}
        severity = hint_map.get(severity_hint, 5)

        event_type = alert.get("event_type", "unknown")

        return TriageResult(
            severity=severity,
            threshold=self.threshold,
            category=event_type,
            summary=f"[FALLBACK] Model unavailable ({error_msg[:100]}). "
            f"Severity estimated from alert hints. Manual review required.",
            recommended_action="Model unavailable — route to SOC analyst for manual triage.",
        )
