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
    base_url: str = "http://localhost:11434"
    timeout: int = 120

    def complete(self, prompt: str) -> str:
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode()
        req = Request(self.base_url.rstrip('/') + '/api/generate', data=body, headers={'Content-Type':'application/json'})
        with urlopen(req, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode('utf-8'))
        return str(payload.get('response', ''))
