"""Tests for the portable InstaBox cloud execution layer (mission Part A).

These exercise the real code paths: the client's request building, header
handling, error mapping, machine resolution, engagement isolation, and artifact
verification all run unchanged. Only the *network transport* -- the one I/O
boundary -- is replaced by an in-process fake, so no test needs a live machine
and none of them can silently pass by mocking the logic under test.

The fail-closed requirements are the point: a missing credential, a rejected
key, and an absent machine must each abort with a distinct, honest result and
must never fall back to local execution.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse

import pytest

from blackheart import cli
from blackheart.cloud import (
    AuthError,
    CloudConfig,
    CloudError,
    InstaBoxClient,
    MachineNotFound,
    MissingCredential,
    machine_summary,
    machine_is_ready,
    resolve_machine,
)
from blackheart.cloud.run import CloudRunner, new_engagement_id


# --------------------------------------------------------------------------- #
# A fake InstaBox API: real routes, real shapes, no network.
# --------------------------------------------------------------------------- #

class FakeInstaBox:
    """A minimal in-process stand-in for api.instabox.sh.

    It implements the routes BLACKHEART uses with the real response shapes, and
    records every request so a test can assert on headers, bodies and paths.
    """

    def __init__(self, machines=None, *, me_login="tester", auth_status=200):
        self.machines = machines if machines is not None else [self._machine()]
        self.me_login = me_login
        self.auth_status = auth_status
        self.files: dict[str, bytes] = {}
        self.requests: list[dict] = []
        self.exec_log: list[str] = []

    @staticmethod
    def _machine(mid="m_test", name="box", state="running"):
        return {
            "id": mid,
            "name": name,
            "state": state,
            "desiredState": "running",
            "spec": {"vcpus": 4, "memMiB": 8192, "persistentDiskGiB": 20},
            "storage": {"mountPath": "/data", "sizeGiB": 20, "persistent": True},
            "template": {"id": "agent-browser"},
            "guestUser": "user",
        }

    def transport(self, method, url, headers, body, timeout):
        path = urllib.parse.urlparse(url).path
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        self.requests.append({
            "method": method, "url": url, "headers": dict(headers),
            "body": body, "timeout": timeout,
        })
        # Authentication is the caller's key; a bad key is a 401.
        if self.auth_status != 200:
            return self.auth_status, json.dumps(
                {"error": {"code": "unauthorized", "message": "bad key"}}
            ).encode()

        if path == "/v1/me":
            return 200, json.dumps({"login": self.me_login}).encode()

        if path == "/v1/machines" and method == "GET":
            return 200, json.dumps(self.machines).encode()

        if path.startswith("/v1/machines/"):
            rest = path[len("/v1/machines/"):]
            mid = rest.split("/")[0]
            machine = next((m for m in self.machines if m["id"] == mid), None)
            if machine is None:
                return 404, json.dumps(
                    {"error": {"code": "not_found", "message": "no machine"}}
                ).encode()
            tail = rest[len(mid):]
            if tail == "" and method == "GET":
                return 200, json.dumps(machine).encode()
            if tail == "/disk":
                return 200, json.dumps({"filesystems": [
                    {"mount": "/data", "usedPct": 10.0, "level": "ok"}
                ]}).encode()
            if tail == "/exec" and method == "POST":
                return self._exec(json.loads(body.decode()))
            if tail == "/files" and method == "PUT":
                p = query["path"][0]
                self.files[p] = body
                return 201, json.dumps({
                    "path": p, "size": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }).encode()
            if tail == "/files" and method == "GET":
                p = query["path"][0]
                return 200, json.dumps({"path": p, "type": "dir", "entries": []}).encode()
            if tail == "/files/content" and method == "GET":
                p = query["path"][0]
                if p not in self.files:
                    return 404, json.dumps(
                        {"error": {"code": "not_found", "message": "no file"}}
                    ).encode()
                return 200, self.files[p]
        return 404, json.dumps(
            {"error": {"code": "not_found", "message": "route not found"}}
        ).encode()

    def _exec(self, body):
        cmd = body.get("cmd")
        if not isinstance(cmd, str):
            return 400, json.dumps(
                {"error": {"code": "bad_request", "message": "field cmd must be a string"}}
            ).encode()
        self.exec_log.append(cmd)
        if cmd.startswith("mkdir"):
            stdout = ""
        elif cmd.startswith("sha256sum"):
            path = cmd.split("'")[1] if "'" in cmd else cmd.split()[-1]
            data = self.files.get(path, b"")
            stdout = f"{hashlib.sha256(data).hexdigest()}  {path}\n"
        elif cmd.startswith("python3"):
            # The remote self-test: facts that only the machine would know.
            stdout = json.dumps({
                "nonce": "abc", "hostname": "instabox-remote",
                "kernel": "6.18.60-instabox", "machine": "x86_64",
                "cpu_count": 4, "python": "3.13.5", "time": 1.0,
            }) + "\n"
        elif "blackheart-remote-ok" in cmd:
            stdout = "blackheart-remote-ok\n"
        else:
            stdout = "ok\n"
        return 200, json.dumps({
            "stdout": stdout, "stderr": "", "exitCode": 0,
            "timedOut": False, "truncated": False, "oomKilled": False,
            "durationMs": 5,
        }).encode()


def make_client(fake: FakeInstaBox, key="ibk_test_key") -> InstaBoxClient:
    return InstaBoxClient("https://api.instabox.sh", key, transport=fake.transport)


# --------------------------------------------------------------------------- #
# Configuration and credential handling
# --------------------------------------------------------------------------- #

def test_config_reads_credential_from_env_only():
    cfg = CloudConfig.from_env({"INSTABOX_API_KEY": "ibk_abc"}, workdir_root="/tmp/x")
    assert cfg.has_credential is True
    assert cfg.api_key == "ibk_abc"


def test_config_to_dict_never_exposes_the_key():
    cfg = CloudConfig.from_env({"INSTABOX_API_KEY": "ibk_super_secret_value"})
    d = cfg.to_dict()
    assert d["credential"] == "present"
    assert "ibk_super_secret_value" not in json.dumps(d)


def test_client_refuses_to_construct_without_a_key():
    with pytest.raises(MissingCredential):
        InstaBoxClient("https://api.instabox.sh", "")


def test_client_repr_redacts_the_key():
    client = InstaBoxClient("https://api.instabox.sh", "ibk_secret_value_xyz")
    assert "ibk_secret_value_xyz" not in repr(client)
    assert "redacted" in repr(client)


def test_key_is_sent_in_header_and_never_in_the_url_or_body():
    fake = FakeInstaBox()
    client = make_client(fake, key="ibk_header_key")
    client.me()
    req = fake.requests[0]
    assert req["headers"]["X-API-Key"] == "ibk_header_key"
    assert "ibk_header_key" not in req["url"]
    assert req["body"] is None


# --------------------------------------------------------------------------- #
# Error mapping
# --------------------------------------------------------------------------- #

def test_rejected_credential_raises_auth_error():
    fake = FakeInstaBox(auth_status=401)
    client = make_client(fake)
    with pytest.raises(AuthError):
        client.me()


def test_server_error_surfaces_the_message():
    fake = FakeInstaBox()
    client = make_client(fake)
    with pytest.raises(CloudError) as exc:
        client.get_machine("m_missing")
    assert "no machine" in str(exc.value)


# --------------------------------------------------------------------------- #
# Machine resolution -- reuse, never create or guess
# --------------------------------------------------------------------------- #

def test_resolve_by_selector_id_and_name():
    fake = FakeInstaBox([FakeInstaBox._machine("m_1", "alpha"),
                         FakeInstaBox._machine("m_2", "beta")])
    client = make_client(fake)
    assert resolve_machine(client, "m_2")["name"] == "beta"
    assert resolve_machine(client, "beta")["id"] == "m_2"


def test_resolve_single_running_machine():
    fake = FakeInstaBox([FakeInstaBox._machine("m_1", "solo")])
    assert resolve_machine(make_client(fake), None)["name"] == "solo"


def test_resolve_refuses_when_none_running():
    fake = FakeInstaBox([FakeInstaBox._machine("m_1", "stopped", state="stopped")])
    with pytest.raises(MachineNotFound):
        resolve_machine(make_client(fake), None)


def test_resolve_accepts_suspended_machine():
    # A persistent box that idled into auto-suspend is usable: an exec wakes it.
    # This is the normal state in a fresh conversation, so discovery must select
    # it rather than report "no usable machine".
    fake = FakeInstaBox([FakeInstaBox._machine("m_1", "idle", state="suspended")])
    m = resolve_machine(make_client(fake), None)
    assert m["name"] == "idle"
    assert machine_is_ready(m)


def test_resolve_accepts_paused_machine():
    fake = FakeInstaBox([FakeInstaBox._machine("m_1", "paused", state="paused")])
    assert resolve_machine(make_client(fake), None)["name"] == "paused"


def test_resolve_counts_wakeable_states_together():
    # One suspended and one running machine is still ambiguous: refuse to guess.
    fake = FakeInstaBox([
        FakeInstaBox._machine("m_1", "a", state="running"),
        FakeInstaBox._machine("m_2", "b", state="suspended"),
    ])
    with pytest.raises(CloudError) as exc:
        resolve_machine(make_client(fake), None)
    assert "never guesses" in str(exc.value)


def test_resolve_refuses_stopped_even_with_running_sibling():
    # A stopped machine cannot be woken by an exec, so it is not selectable; the
    # single running sibling is chosen.
    fake = FakeInstaBox([
        FakeInstaBox._machine("m_1", "live", state="running"),
        FakeInstaBox._machine("m_2", "dead", state="stopped"),
    ])
    assert resolve_machine(make_client(fake), None)["name"] == "live"


def test_machine_is_ready_states():
    assert machine_is_ready({"state": "running"})
    assert machine_is_ready({"state": "suspended"})
    assert machine_is_ready({"state": "paused"})
    assert not machine_is_ready({"state": "stopped"})
    assert not machine_is_ready({"state": "deleted"})
    assert not machine_is_ready({})


def test_resolve_refuses_to_guess_between_several_running():
    fake = FakeInstaBox([FakeInstaBox._machine("m_1", "a"),
                         FakeInstaBox._machine("m_2", "b")])
    with pytest.raises(CloudError) as exc:
        resolve_machine(make_client(fake), None)
    assert "never guesses" in str(exc.value)


def test_machine_summary_is_compact_and_has_no_secrets():
    s = machine_summary(FakeInstaBox._machine())
    assert s["vcpus"] == 4 and s["persistent_disk_gib"] == 20
    assert "ibk" not in json.dumps(s)


# --------------------------------------------------------------------------- #
# Exec
# --------------------------------------------------------------------------- #

def test_exec_builds_the_documented_body():
    fake = FakeInstaBox()
    client = make_client(fake)
    client.exec("m_test", "echo hi", cwd="/data/x", envs={"A": "b"}, timeout_seconds=30)
    body = json.loads(fake.requests[-1]["body"].decode())
    assert body == {"cmd": "echo hi", "cwd": "/data/x", "envs": {"A": "b"},
                    "timeoutSeconds": 30}


def test_exec_rejects_a_timeout_over_the_api_limit():
    fake = FakeInstaBox()
    client = make_client(fake)
    with pytest.raises(CloudError):
        client.exec("m_test", "sleep 1", timeout_seconds=601)


def test_exec_maps_the_response():
    fake = FakeInstaBox()
    res = make_client(fake).exec("m_test", "echo blackheart-remote-ok")
    assert res.ok and "blackheart-remote-ok" in res.stdout


# --------------------------------------------------------------------------- #
# Engagement isolation and artifacts
# --------------------------------------------------------------------------- #

def test_engagement_ids_are_unique_and_filesystem_safe():
    ids = {new_engagement_id() for _ in range(200)}
    assert len(ids) == 200
    for eid in ids:
        assert "/" not in eid and " " not in eid


def test_two_engagements_never_share_a_directory():
    fake = FakeInstaBox()
    client = make_client(fake)
    machine = fake.machines[0]
    a = CloudRunner(client, machine, "eng-a", workdir_root="/tmp/bh")
    b = CloudRunner(client, machine, "eng-b", workdir_root="/tmp/bh")
    assert a.remote_dir != b.remote_dir
    assert a.local_dir != b.local_dir
    assert a.audit_path != b.audit_path


def test_runner_creates_the_remote_directory():
    fake = FakeInstaBox()
    runner = CloudRunner(make_client(fake), fake.machines[0], "eng-x", workdir_root="/tmp/bh")
    runner.create()
    assert any(c.startswith("mkdir -p") for c in fake.exec_log)


def test_cleanup_removes_remote_and_local_scratch(tmp_path):
    fake = FakeInstaBox()
    runner = CloudRunner(make_client(fake), fake.machines[0], "eng-clean",
                         workdir_root=str(tmp_path))
    runner.create()
    assert runner.local_dir.is_dir()
    runner.cleanup()
    assert any(c.startswith("rm -rf") and runner.remote_dir in c
               for c in fake.exec_log)
    assert not runner.local_dir.exists()


def test_cleanup_never_raises_when_the_machine_is_unreachable(tmp_path):
    fake = FakeInstaBox()
    runner = CloudRunner(make_client(fake), fake.machines[0], "eng-gone",
                         workdir_root=str(tmp_path))
    runner.create()

    def boom(*_a, **_k):
        raise CloudError("machine unreachable")

    runner.client.exec = boom  # type: ignore[method-assign]
    runner.cleanup()  # must not raise
    assert not runner.local_dir.exists()


def test_artifact_round_trip_is_verified(tmp_path):
    fake = FakeInstaBox()
    runner = CloudRunner(make_client(fake), fake.machines[0], "eng-art",
                         workdir_root=str(tmp_path))
    runner.create()
    payload = b"remote artifact bytes\n"
    remote = f"{runner.remote_dir}/out.txt"
    fake.files[remote] = payload
    art = runner.fetch_artifact(remote)
    assert art.verified is True
    assert art.sha256 == hashlib.sha256(payload).hexdigest()
    assert (tmp_path / "eng-art" / "out.txt").read_bytes() == payload


def test_artifact_hash_mismatch_is_rejected(tmp_path):
    fake = FakeInstaBox()
    runner = CloudRunner(make_client(fake), fake.machines[0], "eng-bad",
                         workdir_root=str(tmp_path))
    runner.create()
    remote = f"{runner.remote_dir}/out.txt"
    fake.files[remote] = b"real bytes"
    # The machine reports a different hash than the bytes it serves: the transfer
    # is not trustworthy and must be refused, not written as if it verified.
    original = fake._exec

    def lying_exec(body):
        if body.get("cmd", "").startswith("sha256sum"):
            return 200, json.dumps({
                "stdout": "0" * 64 + "  x\n", "stderr": "", "exitCode": 0,
                "timedOut": False, "truncated": False, "oomKilled": False,
                "durationMs": 1,
            }).encode()
        return original(body)

    fake._exec = lying_exec
    with pytest.raises(Exception) as exc:
        runner.fetch_artifact(remote)
    assert "mismatch" in str(exc.value)


def test_audit_log_records_output_hashes_not_output(tmp_path):
    """The audit records the command and *hashes* of its output, never the output.

    The command text is recorded by design (the boundary must be auditable); the
    command's stdout/stderr must not be, or the log becomes a copy of private
    research results.
    """
    fake = FakeInstaBox()
    runner = CloudRunner(make_client(fake), fake.machines[0], "eng-audit",
                         workdir_root=str(tmp_path))
    runner.create()
    runner.execute("echo hi")
    records = [json.loads(l) for l in runner.audit_path.read_text().splitlines() if l.strip()]
    exec_recs = [r for r in records if r.get("event") == "exec"]
    assert exec_recs
    for r in exec_recs:
        assert "stdout_sha256" in r and "stderr_sha256" in r
        assert "stdout" not in r and "stderr" not in r


def test_concurrent_engagements_do_not_share_state(tmp_path):
    """Simultaneous conversations must not corrupt each other's engagement."""
    import threading

    fake = FakeInstaBox()
    client = make_client(fake)
    machine = fake.machines[0]
    runners: dict[str, CloudRunner] = {}

    def work(eid):
        r = CloudRunner(client, machine, eid, workdir_root=str(tmp_path))
        r.create()
        r.execute(f"echo {eid}")
        runners[eid] = r

    threads = [threading.Thread(target=work, args=(f"eng-{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(runners) == 4
    assert len({r.remote_dir for r in runners.values()}) == 4
    for eid, r in runners.items():
        records = [json.loads(l) for l in r.audit_path.read_text().splitlines() if l.strip()]
        # Each engagement's log carries only its own records.
        assert records and all(rec["engagement"] == eid for rec in records)


def test_remote_self_test_proves_remote(tmp_path):
    fake = FakeInstaBox()
    runner = CloudRunner(make_client(fake), fake.machines[0], "eng-self",
                         workdir_root=str(tmp_path))
    runner.create()
    result = runner.remote_self_test()
    assert result["remote_facts"]["hostname"] == "instabox-remote"
    assert result["distinct_from_local"] is True
    assert result["artifact"]["verified"] is True


# --------------------------------------------------------------------------- #
# CLI: fail-closed behaviour and end-to-end paths
# --------------------------------------------------------------------------- #

def test_cli_doctor_missing_credential_exits_3(monkeypatch, capsys):
    monkeypatch.delenv("INSTABOX_API_KEY", raising=False)
    rc = cli.main(["cloud", "doctor"])
    assert rc == cli.EXIT_CLOUD_NO_CREDENTIAL
    assert "never falls back to local execution" in capsys.readouterr().err


def test_cli_doctor_rejected_credential_exits_4(monkeypatch, capsys):
    fake = FakeInstaBox(auth_status=401)
    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_bad")
    monkeypatch.setattr("blackheart.cloud._default_transport", fake.transport)
    rc = cli.main(["cloud", "doctor"])
    assert rc == cli.EXIT_CLOUD_AUTH


def test_cli_connect_unknown_machine_exits_5(monkeypatch, capsys):
    fake = FakeInstaBox()
    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_ok")
    monkeypatch.setattr("blackheart.cloud._default_transport", fake.transport)
    rc = cli.main(["cloud", "connect", "--machine", "nope"])
    assert rc == cli.EXIT_CLOUD_NO_MACHINE
    assert "no machine" in capsys.readouterr().err


def test_cli_doctor_succeeds_end_to_end(monkeypatch, capsys, tmp_path):
    fake = FakeInstaBox()
    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_ok")
    monkeypatch.setattr("blackheart.cloud._default_transport", fake.transport)
    rc = cli.main(["cloud", "doctor", "--workdir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_CLOUD_OK
    assert "genuine remote (not local)" in out
    assert "artifact round-trip verified" in out
    # The credential must never be printed.
    assert "ibk_ok" not in out


def test_cli_execute_runs_and_fetches_artifact(monkeypatch, capsys, tmp_path):
    fake = FakeInstaBox()
    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_ok")
    monkeypatch.setattr("blackheart.cloud._default_transport", fake.transport)
    remote = "/data/home/.blackheart/engagements/e1/out.txt"
    fake.files[remote] = b"artifact\n"
    rc = cli.main([
        "cloud", "execute", "--workdir", str(tmp_path), "--engagement", "e1",
        "--artifact", remote, "--artifact-name", "out.txt", "--", "echo hi",
    ])
    out = capsys.readouterr().out
    assert rc == cli.EXIT_CLOUD_OK
    assert "verified=True" in out
    assert (tmp_path / "e1" / "out.txt").read_bytes() == b"artifact\n"


def test_cli_execute_propagates_the_command_exit_code(monkeypatch, tmp_path):
    fake = FakeInstaBox()
    original = fake._exec

    def failing_exec(body):
        # Directory setup still succeeds; only the workload command fails.
        if body.get("cmd", "").startswith("mkdir"):
            return original(body)
        return 200, json.dumps({
            "stdout": "", "stderr": "boom", "exitCode": 7,
            "timedOut": False, "truncated": False, "oomKilled": False,
            "durationMs": 1,
        }).encode()

    fake._exec = failing_exec
    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_ok")
    monkeypatch.setattr("blackheart.cloud._default_transport", fake.transport)
    rc = cli.main(["cloud", "execute", "--workdir", str(tmp_path), "--", "false"])
    assert rc == 7


def test_cli_artifacts_verifies_local_files(monkeypatch, capsys, tmp_path):
    fake = FakeInstaBox()
    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_ok")
    monkeypatch.setattr("blackheart.cloud._default_transport", fake.transport)
    remote = "/data/home/.blackheart/engagements/e1/out.txt"
    fake.files[remote] = b"artifact\n"
    cli.main(["cloud", "execute", "--workdir", str(tmp_path), "--engagement", "e1",
              "--artifact", remote, "--artifact-name", "out.txt", "--", "echo hi"])
    capsys.readouterr()
    rc = cli.main(["cloud", "artifacts", "--workdir", str(tmp_path)])
    assert rc == cli.EXIT_CLOUD_OK
    assert "[ok]" in capsys.readouterr().out


def test_network_failure_never_falls_back_to_local(monkeypatch, capsys, tmp_path):
    """When the cloud is unreachable the command must fail, not run locally."""
    def boom(method, url, headers, body, timeout):
        raise ConnectionError("network down")

    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_ok")
    monkeypatch.setattr("blackheart.cloud._default_transport", boom)

    sentinel = tmp_path / "this-would-exist-if-run-locally"
    rc = cli.main(["cloud", "execute", "--workdir", str(tmp_path), "--",
                   f"touch {sentinel}"])
    assert rc == cli.EXIT_CLOUD_FAILED
    assert not sentinel.exists(), "cloud execution must never fall back to local"
    assert "network error" in capsys.readouterr().err


def test_cli_artifacts_detects_a_modified_file(monkeypatch, capsys, tmp_path):
    fake = FakeInstaBox()
    monkeypatch.setenv("INSTABOX_API_KEY", "ibk_ok")
    monkeypatch.setattr("blackheart.cloud._default_transport", fake.transport)
    remote = "/data/home/.blackheart/engagements/e1/out.txt"
    fake.files[remote] = b"artifact\n"
    cli.main(["cloud", "execute", "--workdir", str(tmp_path), "--engagement", "e1",
              "--artifact", remote, "--artifact-name", "out.txt", "--", "echo hi"])
    (tmp_path / "e1" / "out.txt").write_bytes(b"tampered\n")
    capsys.readouterr()
    rc = cli.main(["cloud", "artifacts", "--workdir", str(tmp_path)])
    assert rc == cli.EXIT_CLOUD_FAILED
    assert "[!!]" in capsys.readouterr().out
