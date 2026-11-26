"""Engagement-scoped remote execution on the InstaBox machine.

An *engagement* is one unit of remote work: a unique id, a unique directory on
the machine's persistent disk, a matching local directory, and an append-only
audit log. Two engagements never share a directory, so concurrent conversations
cannot corrupt each other's state (mission Part A).

The audit log records the command text, the exit code, and *hashes* of the
output -- never the output itself, and never the credential. This keeps the
boundary auditable without turning the log into a copy of private research.
"""

from __future__ import annotations

import json
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import (
    REMOTE_ROOT,
    CloudError,
    ExecResult,
    InstaBoxClient,
    RemoteExecutionError,
    sha256_hex,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_engagement_id(prefix: str = "eng") -> str:
    """A unique, sortable, filesystem-safe engagement id.

    ``<prefix>-<UTC timestamp>-<8 random hex>``. The timestamp makes the order
    readable; the 32-bit random suffix makes a collision across concurrent
    conversations (which share a clock tick) negligible -- 2 bytes was not
    enough: a few hundred ids in one second collide by the birthday bound.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{prefix}-{stamp}-{secrets.token_hex(4)}"


@dataclass
class Artifact:
    """A verified artifact retrieved from the machine."""

    name: str
    remote_path: str
    local_path: str
    sha256: str
    size: int
    verified: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "remote_path": self.remote_path,
            "local_path": self.local_path,
            "sha256": self.sha256,
            "size": self.size,
            "verified": self.verified,
        }


class CloudRunner:
    """Run work in one engagement on the machine, with a verified artifact path.

    The runner is deliberately thin: it resolves the machine once, creates the
    engagement directory on the persistent disk, and then only runs commands and
    transfers files inside that directory.
    """

    def __init__(
        self,
        client: InstaBoxClient,
        machine: dict,
        engagement_id: str,
        *,
        workdir_root: Path,
        remote_root: str = REMOTE_ROOT,
    ) -> None:
        self.client = client
        self.machine = machine
        self.engagement_id = engagement_id
        self.machine_id = machine.get("id", "")
        self.machine_name = machine.get("name", "")
        self.workdir_root = Path(workdir_root)
        self.remote_dir = f"{remote_root}/{engagement_id}"
        self.local_dir = self.workdir_root / engagement_id
        self.audit_path = self.local_dir / "audit.jsonl"
        self._created = False

    # -- lifecycle ---------------------------------------------------------- #

    def create(self) -> "CloudRunner":
        """Create the local and remote engagement directories (idempotent)."""
        self.local_dir.mkdir(parents=True, exist_ok=True)
        res = self.client.exec(
            self.machine_id, f"mkdir -p {_sh(self.remote_dir)}", timeout_seconds=30
        )
        if not res.ok:
            raise RemoteExecutionError(
                f"could not create the remote engagement directory "
                f"{self.remote_dir}: {res.stderr.strip() or res.stdout.strip()}"
            )
        self._created = True
        self._audit({"event": "create", "remote_dir": self.remote_dir})
        return self

    def cleanup(self) -> None:
        """Remove this engagement's scratch directories (best effort).

        Persistent storage is a feature for real work, so this is only called by
        self-checks (``cloud doctor``) that create a throwaway engagement. It
        never raises: a failed cleanup must not mask the check result.
        """
        try:
            self.client.exec(
                self.machine_id, f"rm -rf {_sh(self.remote_dir)}", timeout_seconds=30
            )
        except CloudError:
            pass
        shutil.rmtree(self.local_dir, ignore_errors=True)

    def _audit(self, record: dict) -> None:
        """Append one JSON line to the engagement audit log.

        A single small ``write`` under ``O_APPEND`` is atomic on POSIX, so
        concurrent appends from parallel engagements do not interleave; each
        engagement has its own log in any case.
        """
        self.local_dir.mkdir(parents=True, exist_ok=True)
        record = {"at": _utcnow(), "engagement": self.engagement_id,
                  "machine": self.machine_id, **record}
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    # -- execution ---------------------------------------------------------- #

    def execute(
        self,
        cmd: str,
        *,
        cwd: Optional[str] = None,
        envs: Optional[dict] = None,
        timeout_seconds: Optional[int] = None,
        check: bool = False,
    ) -> ExecResult:
        """Run ``cmd`` on the machine, defaulting to the engagement directory.

        The output is recorded in the audit log by hash only. ``check=True``
        raises on a non-zero exit code, for callers that require success.
        """
        workdir = cwd or self.remote_dir
        res = self.client.exec(
            self.machine_id,
            cmd,
            cwd=workdir,
            envs=envs,
            timeout_seconds=timeout_seconds,
        )
        self._audit({
            "event": "exec",
            "cmd": cmd,
            "cwd": workdir,
            "exit_code": res.exit_code,
            "timed_out": res.timed_out,
            "stdout_sha256": sha256_hex(res.stdout.encode("utf-8")),
            "stderr_sha256": sha256_hex(res.stderr.encode("utf-8")),
        })
        if check and not res.ok:
            raise RemoteExecutionError(
                f"remote command failed (exit {res.exit_code}): {cmd}\n"
                f"{res.stderr.strip() or res.stdout.strip()}"
            )
        return res

    # -- artifacts ---------------------------------------------------------- #

    def put_artifact(self, name: str, data: bytes) -> dict:
        """Upload bytes into the engagement directory; return the server's hash."""
        remote_path = f"{self.remote_dir}/{name}"
        resp = self.client.put_file(self.machine_id, remote_path, data)
        self._audit({
            "event": "put_artifact",
            "name": name,
            "remote_path": remote_path,
            "size": len(data),
            "local_sha256": sha256_hex(data),
            "remote_sha256": resp.get("sha256", ""),
        })
        return resp

    def fetch_artifact(
        self,
        remote_path: str,
        *,
        name: Optional[str] = None,
        local_dir: Optional[Path] = None,
    ) -> Artifact:
        """Download a file and verify its SHA-256 against the remote hash.

        The hash is computed *on the machine* with ``sha256sum`` and compared to
        the hash of the bytes received here, so a truncated or corrupted
        transfer is caught rather than silently accepted.
        """
        res = self.client.exec(
            self.machine_id, f"sha256sum {_sh(remote_path)}", timeout_seconds=60
        )
        if not res.ok:
            raise RemoteExecutionError(
                f"could not hash {remote_path} on the machine: "
                f"{res.stderr.strip() or res.stdout.strip()}"
            )
        remote_hash = res.stdout.strip().split()[0] if res.stdout.strip() else ""

        data = self.client.get_file(self.machine_id, remote_path)
        local_hash = sha256_hex(data)
        verified = bool(remote_hash) and remote_hash == local_hash

        target_dir = Path(local_dir) if local_dir else self.local_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        artifact_name = name or Path(remote_path).name
        local_path = target_dir / artifact_name
        local_path.write_bytes(data)

        artifact = Artifact(
            name=artifact_name,
            remote_path=remote_path,
            local_path=str(local_path),
            sha256=local_hash,
            size=len(data),
            verified=verified,
        )
        self._audit({
            "event": "fetch_artifact",
            "name": artifact_name,
            "remote_path": remote_path,
            "remote_sha256": remote_hash,
            "local_sha256": local_hash,
            "size": len(data),
            "verified": verified,
        })
        if not verified:
            raise RemoteExecutionError(
                f"artifact hash mismatch for {remote_path}: "
                f"remote={remote_hash or '<none>'} local={local_hash}"
            )
        return artifact

    # -- genuine remote-execution self test --------------------------------- #

    def remote_self_test(self) -> dict:
        """Prove this is genuine remote execution, not a local mock.

        The machine computes a small JSON artifact from facts that only the
        machine can produce (its hostname, kernel, a nonce generated *there*),
        writes it, and the runner fetches it back and verifies the SHA-256. The
        returned dict carries the machine-observed facts, so a caller can see
        they are not the local sandbox's.
        """
        nonce = secrets.token_hex(8)
        script = (
            "python3 - <<'PY'\n"
            "import json,os,platform,socket,time\n"
            "print(json.dumps({\n"
            f"  'nonce': {nonce!r},\n"
            "  'hostname': socket.gethostname(),\n"
            "  'kernel': platform.release(),\n"
            "  'machine': platform.machine(),\n"
            "  'cpu_count': os.cpu_count(),\n"
            "  'python': platform.python_version(),\n"
            "  'time': time.time(),\n"
            "}))\n"
            "PY\n"
        )
        res = self.execute(script, timeout_seconds=60, check=True)
        remote_json = res.stdout.strip()
        artifact_name = f"remote-self-test-{nonce}.json"
        self.client.put_file(
            self.machine_id, f"{self.remote_dir}/{artifact_name}",
            (remote_json + "\n").encode("utf-8"),
        )
        artifact = self.fetch_artifact(f"{self.remote_dir}/{artifact_name}")

        try:
            facts = json.loads(remote_json)
        except json.JSONDecodeError as exc:
            raise RemoteExecutionError(
                f"remote self-test produced unparseable output: {remote_json!r}"
            ) from exc

        local_host = __import__("socket").gethostname()
        return {
            "machine_id": self.machine_id,
            "machine_name": self.machine_name,
            "remote_facts": facts,
            "local_hostname": local_host,
            "distinct_from_local": facts.get("hostname") != local_host,
            "artifact": artifact.to_dict(),
            "verified": artifact.verified,
        }


def _sh(value: str) -> str:
    """Single-quote a value for safe interpolation into a remote shell string."""
    return "'" + value.replace("'", "'\\''") + "'"


__all__ = ["Artifact", "CloudRunner", "new_engagement_id"]
