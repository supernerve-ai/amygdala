"""Foundation-Sec triage agent for evaluating alert severity."""

import os
import logging
from dataclasses import dataclass

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


class TriageAgent:
    """Evaluates security alerts using Foundation-Sec model."""

    def __init__(self):
        self.model_endpoint = os.getenv("MODEL_ENDPOINT", "http://localhost:11434")
        self.model_name = os.getenv("MODEL_NAME", "foundation-sec")
        self.threshold = 5
        self._load_prompt()

    def _load_prompt(self):
        """Load triage prompt template."""
        prompt_path = os.path.join(
            os.path.dirname(__file__), "..", "prompts", "triage_prompt.yaml"
        )
        try:
            with open(prompt_path, "r") as f:
                self.prompt_config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning("Triage prompt not found, using defaults")
            self.prompt_config = {"system": "You are a security triage analyst."}

    async def evaluate(self, alert: dict) -> TriageResult:
        """Evaluate an alert and return triage result."""
        prompt = self._build_prompt(alert)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.model_endpoint}/api/generate",
                json={
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False,
                },
            )
            response.raise_for_status()
            result = response.json()

        return self._parse_response(result.get("response", ""))

    def _build_prompt(self, alert: dict) -> str:
        """Build the triage prompt from template and alert data."""
        system = self.prompt_config.get("system", "")
        return f"{system}\n\nAlert Data:\n{alert}"

    def _parse_response(self, response_text: str) -> TriageResult:
        """Parse model response into structured TriageResult."""
        # Default parsing - extend with structured output parsing
        return TriageResult(
            severity=5,
            threshold=self.threshold,
            category="unknown",
            summary=response_text[:200],
            recommended_action="investigate",
        )
