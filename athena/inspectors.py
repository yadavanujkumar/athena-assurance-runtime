from __future__ import annotations

from pathlib import Path

from .models import Finding, Severity


class ProjectInspector:
    """Build higher-level assurance signals from the discovered project."""

    def inspect(self, root: str | Path, graph) -> list[Finding]:
        root = Path(root)
        findings: list[Finding] = []
        names = {e.name.lower() for e in graph.entities.values()}
        markers = {"openai", "anthropic", "langchain", "langgraph", "transformers", "torch", "tensorflow", "ollama", "llama", "agent", "prompt"}
        hits = sorted(x for x in names if any(marker in x for marker in markers))
        if hits:
            findings.append(Finding("AI-DETECTED", "AI components detected", "AI or agent-related components were discovered. ATHENA should extend assurance into models, prompts, tools, data and authority boundaries.", Severity.INFO, 0.75, hits, "Create an AI system inventory and assess model, data, prompt, tool and deployment controls."))
        manifests = ["pyproject.toml", "requirements.txt", "package.json", "pom.xml", "go.mod", "Cargo.toml"]
        found = [m for m in manifests if (root / m).exists()]
        if found:
            findings.append(Finding("DEPENDENCY-MANIFESTS", "Dependency manifests detected", "Dependency manifests were found and can be analyzed for supply-chain and vulnerability risk.", Severity.INFO, 0.95, found, "Run an appropriate open-source dependency audit for each ecosystem."))
        return findings
