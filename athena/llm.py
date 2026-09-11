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
    """Opt-in LLM boundary. Deterministic ATHENA reasoning remains authoritative."""

    def __init__(self, provider: ModelProvider | None = None) -> None:
        self.provider = provider

    @classmethod
    def local_ollama(cls, **kwargs) -> "OptionalReasoning":
        return cls(OllamaProvider(**kwargs))

    def augment(self, prompt: str) -> LLMResult:
        if self.provider is None:
            return LLMResult("", "none", False)
        try:
            text = self.provider.complete(prompt).strip()
            return LLMResult(text, type(self.provider).__name__, bool(text))
        except Exception as exc:
            return LLMResult("", type(self.provider).__name__, False, f"{type(exc).__name__}: {exc}")
