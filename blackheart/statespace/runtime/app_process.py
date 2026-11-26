"""Run a harness app as a local process speaking the line-JSON protocol.

Used by the process execution adapter. Reads one JSON request per line from stdin
and writes one JSON response per line to stdout. ``__reset__`` and ``__state__``
are reserved operations. Unknown operations return 404; a handler fault returns
500. Nothing is written to stdout except protocol responses (diagnostics go to
stderr), so the protocol stays parseable.
"""

from __future__ import annotations

import json
import sys

from .harness_apps import make_app


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: app_process <app-name>", file=sys.stderr)
        return 2
    app = make_app(argv[1])
    state = app.initial_state()
    ops = {op.name: op for op in app.ops()}
    roles = app.roles()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            sys.stdout.write(json.dumps({"status": 400, "body": {"error": "bad json"}}) + "\n")
            sys.stdout.flush()
            continue
        op = req.get("op", "")
        actor = req.get("actor", "")
        params = req.get("params", {}) or {}
        if op == "__reset__":
            state = app.initial_state()
            resp = {"status": 200, "body": {"reset": True}}
        elif op == "__state__":
            resp = {"status": 200, "body": {"state": app.snapshot(state)}}
        elif op in ops:
            spec = ops[op]
            if spec.roles and not (set(spec.roles) & set(roles.get(actor, ()))):
                resp = {"status": 403, "body": {"error": "role not permitted"}}
            else:
                try:
                    status, body = spec.handler(state, actor, params)
                    resp = {"status": status, "body": body}
                except Exception as exc:  # noqa: BLE001
                    resp = {"status": 500, "body": {"error": f"{type(exc).__name__}: {exc}"}}
        else:
            resp = {"status": 404, "body": {"error": f"unknown operation {op!r}"}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
