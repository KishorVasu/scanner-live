"""LLM boundary. The Anthropic implementation arrives in Phase 4; every call already goes through the gateway."""

import html
import re
from typing import Any, Protocol


class LLMProvider(Protocol):
    async def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send a Messages API request; return the response with `usage` and `content`."""
        ...


def data_block(source: str, source_id: str, content: str) -> str:
    """Wrap untrusted text (rule R3). A closing tag inside content cannot end the block."""
    safe = re.sub(r"(?i)<(/?)untrusted_data", r"&lt;\1untrusted_data", content)
    attrs = f'source="{html.escape(source)}" source_id="{html.escape(source_id)}"'
    return f"<untrusted_data {attrs}>\n{safe}\n</untrusted_data>"
