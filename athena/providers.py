from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
import json
from urllib.request import Request, urlopen

class ModelProvider(Protocol):
    """Minimal provider contract. The runtime does not require an LLM."""
    def complete(self, prompt: str) -> str: ...

@dataclass
class OllamaProvider:
    """Optional local Ollama adapter; no hosted API is required."""
    model: str = "llama3.2"
    host: str = "http://localhost:11434"
    timeout: int = 120

    # Keep 'base_url' as a backwards-compatible alias (deprecated).
    def __post_init__(self) -> None:
        # Nothing to do; host is the canonical field name.
        pass

    def complete(self, prompt: str) -> str:
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode()
        url = self.host.rstrip('/') + '/api/generate'
        req = Request(url, data=body, headers={'Content-Type': 'application/json'})
        with urlopen(req, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))
        return str(payload.get('response', ''))
