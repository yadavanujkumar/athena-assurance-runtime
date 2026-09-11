from __future__ import annotations

from dataclasses import dataclass

from .providers import ModelProvider, OllamaProvider


@dataclass(frozen=True, slots=True)
class LLMResult:
    text: str
    provider: str
    used: bool
    error: str | None = None


class OptionalReasoning:
    """Opt-in advisory LLM boundary; model output can never select an ATHENA action."""

    MAX_PROMPT_CHARS = 12000
    MAX_OUTPUT_CHARS = 12000

    def __init__(self, provider: ModelProvider | None = None) -> None:
        self.provider = provider

    @classmethod
    def local_ollama(cls, **kwargs) -> "OptionalReasoning":
        return cls(OllamaProvider(**kwargs))

    @property
    def enabled(self) -> bool:
        return self.provider is not None

    def augment(self, prompt: str) -> LLMResult:
        if self.provider is None:
            return LLMResult("", "none", False)
        prompt = str(prompt)
        if len(prompt) > self.MAX_PROMPT_CHARS:
            prompt = prompt[: self.MAX_PROMPT_CHARS] + "\n[ATHENA prompt truncated]"
        try:
            text = self.provider.complete(prompt).strip()
            if len(text) > self.MAX_OUTPUT_CHARS:
                text = text[: self.MAX_OUTPUT_CHARS] + "\n[ATHENA output truncated]"
            return LLMResult(text, type(self.provider).__name__, bool(text))
        except Exception as exc:
            return LLMResult("", type(self.provider).__name__, False, f"{type(exc).__name__}: {exc}")
