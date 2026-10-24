"""Send one small, non-destructive live request using the configured Gemini key."""

import sys

from pydantic import BaseModel, ConfigDict

from app.core.config import get_settings
from app.services.ai_provider import AIProviderError, AIProviderUnavailable, generate_structured


class SmokeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool


def main() -> int:
    settings = get_settings()
    if settings.ai_provider != "gemini":
        print("Set FAILPROOF_AI_PROVIDER=gemini in the backend .env before running this smoke test.", file=sys.stderr)
        return 2
    try:
        result, provider, model = generate_structured(
            'Return a JSON object with "ok": true. This is a connectivity check; perform no actions.',
            SmokeResponse,
        )
    except (AIProviderError, AIProviderUnavailable) as exc:
        print(f"Gemini live smoke test failed: {exc}", file=sys.stderr)
        return 1
    if not result.ok:
        print("Gemini live smoke test failed: response did not satisfy the check.", file=sys.stderr)
        return 1
    print(f"Gemini live smoke test succeeded: provider={provider}, model={model}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
