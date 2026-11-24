"""Anthropic Messages API behind LLMProvider. Only the Tool Gateway calls this, after redaction (rules R2, R4).

The key comes from a mounted secret file (`SP_ANTHROPIC_API_KEY_FILE`); it is never logged or stored.
Requests are plain Messages API calls with JSON output (`output_config.format`): the model gets no tools at all.
"""

from typing import Any

import anthropic

from app.core.config import get_settings

# Server-side refusal fallback (opt-in, recommended for claude-opus-5-5): on a policy decline the API re-runs the
# request on a fallback model in the same call. Handlers still treat a final `refusal` as "no LLM answer".
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    def __init__(self, api_key: str, client: anthropic.AsyncAnthropic | None = None) -> None:
        self._client = client or anthropic.AsyncAnthropic(api_key=api_key, max_retries=2, timeout=120.0)

    async def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.beta.messages.create(**request, betas=[FALLBACK_BETA], fallbacks="default")
        return response.to_dict()


def provider_from_settings() -> AnthropicProvider | None:
    """None when no key is mounted: LLM steps are then refused by the gateway and handlers fall back to rules."""
    path = get_settings().anthropic_api_key_file
    key = path.read_text().strip() if path is not None and path.exists() else ""
    return AnthropicProvider(key) if key else None
