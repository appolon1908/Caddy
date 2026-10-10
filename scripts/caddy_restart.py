#!/usr/bin/env python3
"""Supervise Caddy from the shared accepted JSON, with checked startup readiness."""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import time

from caddy_coordination import RuntimeCoordinator, atomic_json
from caddy_runtime_readback import CaddyRuntime, RuntimeReadbackError, validate_configuration, sha256_json


def run_approved(runtime, coordinator, binary, timeout=10.0):
    lock = coordinator.acquire()
    process = None
    handlers = {}
    try:
        config = json.loads(coordinator.active_path.read_text(encoding='utf-8'))
        if not isinstance(config, dict):
            raise ValueError('restart configuration must be an object')
        if not runtime.health_urls:
            raise RuntimeReadbackError('HEALTH_NOT_CONFIGURED', 'restart health probes are required')
        validate_configuration(config)
        # Refuse to collide with an already-running admin listener.
        try:
            runtime.config()
        except RuntimeReadbackError as exc:
            if exc.code != 'ADMIN_API_UNAVAILABLE':
                raise
        else:
            raise RuntimeError('Caddy is already running; restart must stop it first')
        process = subprocess.Popen([binary, 'run', '--config', str(coordinator.active_path)])
        def forward(signum, _frame):
            process.send_signal(signum)
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, forward)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Caddy exited during startup')
            try:
                effective = runtime.config()
                if effective != config:
                    raise RuntimeError('restart readback does not match accepted configuration')
                runtime.check_health()
                break
            except RuntimeReadbackError:
                time.sleep(.05)
        else:
            raise RuntimeError('Caddy restart readiness timed out')
        coordinator.recover_interrupted(config)
        # Startup shares the mutation lock until readiness; running Caddy does not
        # hold it, allowing the two engines to perform serialized activations.
        coordinator.release(lock)
        lock = None
        atomic_json(coordinator.root / "startup.json", {
            "supervisor_pid": os.getpid(), "caddy_pid": process.pid,
            "config_sha256": sha256_json(config), "health_verified": True,
        })
        return process.wait()
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
        if lock is not None:
            coordinator.release(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--caddy-bin', default=os.environ.get('CADDY_BIN', 'caddy'))
    parser.add_argument('--admin-api', default=os.environ.get('CADDY_ADMIN_API', 'http://127.0.0.1:2019'))
    parser.add_argument('--health-url', action='append')
    parser.add_argument('--timeout', type=float, default=10.0)
    args = parser.parse_args()
    if not 0 < args.timeout <= 60:
        parser.error('startup timeout must be between 0 and 60 seconds')
    os.environ['CADDY_BIN'] = args.caddy_bin
    runtime = CaddyRuntime(args.admin_api, health_urls=args.health_url)
    return run_approved(runtime, RuntimeCoordinator(), args.caddy_bin, args.timeout)


if __name__ == '__main__':
    raise SystemExit(main())
