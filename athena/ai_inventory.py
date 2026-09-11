from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AISignal:
    kind: str
    name: str
    source: str
    confidence: float
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


class AIInventory:
    """Read-only discovery of AI/agent components and their trust-boundary signals."""

    PROVIDERS = {
        "openai": "OpenAI",
        "anthropic": "Anthropic",
        "langchain": "LangChain",
        "langgraph": "LangGraph",
        "transformers": "Hugging Face Transformers",
        "torch": "PyTorch",
        "tensorflow": "TensorFlow",
        "ollama": "Ollama",
        "litellm": "LiteLLM",
    }
    MODEL_HINTS = re.compile(r"(?:model|llm)\s*=\s*[\"']([^\"']+)[\"']", re.I)
    TOOL_HINTS = re.compile(r"(?:tool|tools)\s*=\s*\[([^\]]*)\]", re.I | re.S)
    PROMPT_HINTS = re.compile(r"(?:system_prompt|system_message|prompt_template|prompt)\s*=", re.I)

    def scan(self, root: str | Path) -> list[AISignal]:
        root = Path(root).resolve()
        signals: list[AISignal] = []
        for path in root.rglob("*"):
            if not path.is_file() or any(p in {".git", ".athena", ".venv", "venv", "node_modules", "__pycache__"} for p in path.parts):
                continue
            if path.suffix.lower() not in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            lower = text.lower()
            for key, name in self.PROVIDERS.items():
                if key in lower:
                    signals.append(AISignal("provider", name, rel, 0.9, f"Reference to {name} detected."))
            for match in self.MODEL_HINTS.finditer(text):
                signals.append(AISignal("model", match.group(1), rel, 0.7, "Model assignment pattern detected."))
            if self.PROMPT_HINTS.search(text):
                signals.append(AISignal("prompt", rel, rel, 0.7, "Prompt construction or system-message pattern detected."))
            if self.TOOL_HINTS.search(text) or "@tool" in lower or "tool_call" in lower:
                signals.append(AISignal("tool", rel, rel, 0.7, "Tool registration or tool-call pattern detected."))
            if any(x in lower for x in ("requests.get", "requests.post", "httpx.", "urllib.request", "fetch(", "axios.")) and any(x in lower for x in ("agent", "tool", "llm", "model")):
                signals.append(AISignal("network_boundary", rel, rel, 0.65, "AI-related code appears to access network resources."))
            if any(x in lower for x in ("subprocess.", "os.system(", "shell=true", "exec(")) and any(x in lower for x in ("agent", "tool", "llm", "model")):
                signals.append(AISignal("execution_boundary", rel, rel, 0.8, "AI-related code appears to invoke local command execution."))
        return self._dedupe(signals)

    @staticmethod
    def _dedupe(signals: list[AISignal]) -> list[AISignal]:
        seen: set[tuple[str, str, str]] = set()
        result: list[AISignal] = []
        for signal in signals:
            key = (signal.kind, signal.name, signal.source)
            if key not in seen:
                seen.add(key)
                result.append(signal)
        return result
