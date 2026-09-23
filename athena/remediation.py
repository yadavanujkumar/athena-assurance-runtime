from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import tempfile

from .models import Action, Finding


@dataclass(frozen=True, slots=True)
class RemediationStep:
    action: str
    rationale: str
    requires_approval: bool


@dataclass(frozen=True, slots=True)
class PatchProposal:
    """A deterministic patch with a content-hash precondition."""

    finding_id: str
    path: str
    before_sha256: str
    before: str
    after: str
    rationale: str

    @property
    def diff(self) -> str:
        import difflib

        return "".join(
            difflib.unified_diff(
                self.before.splitlines(keepends=True),
                self.after.splitlines(keepends=True),
                fromfile=self.path,
                tofile=self.path,
            )
        )


class RemediationPlanner:
    """Produces bounded remediation plans; it never changes project files itself."""

    def plan(self, finding: Finding, action: Action) -> list[RemediationStep]:
        steps: list[RemediationStep] = []
        if finding.remediation:
            steps.append(RemediationStep(finding.remediation, "Use the detector's evidence-backed remediation guidance.", action is Action.MODIFY))
        if action is Action.MODIFY:
            steps.append(RemediationStep("create_patch", "Prepare a minimal, reviewable change rather than mutating the working tree directly.", True))
            steps.append(RemediationStep("run_validation", "Run relevant tests and assurance checks before accepting the change.", True))
        elif action is Action.RECOMMEND:
            steps.append(RemediationStep("request_approval", "Present the evidence, risk, proposed change and validation plan to an authorized human.", True))
        return steps


class SafeRemediationEngine:
    """Creates narrowly scoped patches and applies them only after explicit approval.

    The engine is deliberately conservative: unsupported or ambiguous findings produce
    no patch. Every write requires the exact content hash captured when the proposal
    was created, and successful writes are atomic and verified before returning.
    """

    def propose(self, root: str | Path, finding: Finding) -> PatchProposal | None:
        root = Path(root).resolve()
        for evidence in finding.evidence:
            parsed = self._evidence_path(evidence, root)
            if parsed is None:
                continue
            path, line_no = parsed
            try:
                before = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            lines = before.splitlines(keepends=True)
            if not 1 <= line_no <= len(lines):
                continue
            line = lines[line_no - 1]
            if finding.title == "Dynamic eval usage" and "eval(" in line and "ast.literal_eval(" not in line:
                lines[line_no - 1] = line.replace("eval(", "ast.literal_eval(", 1)
                after = "".join(lines)
                if "import ast\n" not in after and "import ast\r\n" not in after:
                    lines.insert(0, "import ast\n")
                    after = "".join(lines)
                return PatchProposal(finding.id, path.relative_to(root).as_posix(), hashlib.sha256(before.encode()).hexdigest(), before, after, "Replace direct eval() with ast.literal_eval() for a constrained literal-only parser.")
        return None

    def apply(self, root: str | Path, proposal: PatchProposal, *, approved: bool = False) -> Path:
        if not approved:
            raise PermissionError("remediation requires explicit approval")
        root = Path(root).resolve()
        path = (root / proposal.path).resolve()
        if root not in path.parents and path != root:
            raise ValueError("remediation path escapes project root")
        try:
            current = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise FileNotFoundError(proposal.path) from exc
        if self.sha256(current) != proposal.before_sha256:
            raise RuntimeError("remediation proposal is stale; project file changed since proposal creation")
        self._atomic_write(path, proposal.after)
        try:
            written = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise RuntimeError("remediation write could not be verified") from exc
        if self.sha256(written) != self.sha256(proposal.after):
            raise RuntimeError("remediation write verification failed; file content hash does not match proposal")
        return path

    @staticmethod
    def sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def _atomic_write(cls, path: Path, content: str) -> None:
        import sys
        mode = path.stat().st_mode & 0o777
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.athena-", dir=path.parent)
        temporary_path = Path(temporary)
        try:
            # fchmod is not available on Windows; skip permission copy there.
            if sys.platform != "win32":
                os.fchmod(fd, mode)
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        finally:
            temporary_path.unlink(missing_ok=True)

    @classmethod
    def restore(cls, root: str | Path, proposal: PatchProposal, *, expected_sha256: str) -> Path:
        """Restore the proposal's original content only if no concurrent edit occurred."""
        root = Path(root).resolve()
        path = (root / proposal.path).resolve()
        if root not in path.parents:
            raise ValueError("remediation path escapes project root")
        try:
            current = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise FileNotFoundError(proposal.path) from exc
        if cls.sha256(current) != expected_sha256:
            raise RuntimeError("rollback refused; project file changed after remediation")
        cls._atomic_write(path, proposal.before)
        try:
            restored = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise RuntimeError("rollback could not be verified") from exc
        if cls.sha256(restored) != proposal.before_sha256:
            raise RuntimeError("rollback verification failed; original content hash was not restored")
        return path

    @staticmethod
    def _evidence_path(evidence: str, root: Path) -> tuple[Path, int] | None:
        text = str(evidence)
        if ":" not in text:
            return None
        path_text, line_text = text.rsplit(":", 1)
        try:
            line_no = int(line_text)
        except ValueError:
            return None
        path = Path(path_text)
        if not path.is_absolute():
            path = root / path
        path = path.resolve()
        if root not in path.parents:
            return None
        return path, line_no
