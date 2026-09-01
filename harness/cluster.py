"""Cluster client abstraction for kubectl and oc."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any


class ClusterExecError(RuntimeError):
    """Raised when container exec exits non-zero."""

    def __init__(self, returncode: int, stderr: str, stdout: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        detail = (stderr or stdout or "").strip() or "(no output)"
        super().__init__(f"cluster exec failed (rc={returncode}): {detail}")


# Backward compatibility alias
OcExecError = ClusterExecError


class ClusterClient:
    """Subprocess wrapper for kubectl and oc commands."""

    def __init__(self, bin_path: str | None = None) -> None:
        if bin_path:
            self.bin = bin_path
        else:
            env_bin = os.environ.get("KUBECTL_BIN")
            if env_bin:
                self.bin = env_bin
            elif shutil.which("kubectl"):
                self.bin = "kubectl"
            elif shutil.which("oc"):
                self.bin = "oc"
            else:
                self.bin = "kubectl"

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int | None = None,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [self.bin, *args]
        return subprocess.run(
            cmd,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
            text=text,
        )

    def run_argv(
        self,
        cmd: Sequence[str],
        *,
        timeout: int | None = None,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run a full argv that may already start with oc/kubectl/self.bin."""
        args = list(cmd)
        if args:
            first = args[0]
            if first == self.bin or Path(first).name in {"oc", "kubectl"}:
                args = args[1:]
        return self.run(
            args,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
            text=text,
        )

    def exec(
        self,
        namespace: str,
        target: str,
        script: str,
        *,
        container: str | None = None,
        timeout: int | None = None,
    ) -> str:
        """Run bash -c script inside a pod/deployment container."""
        cmd: list[str] = ["exec", "-n", namespace, target]
        if container:
            cmd.extend(["-c", container])
        cmd.extend(["--", "bash", "-c", script])

        res = self.run(cmd, timeout=timeout)
        if res.returncode != 0:
            raise ClusterExecError(res.returncode, res.stderr, res.stdout)
        return res.stdout

    def apply_text(self, yaml_content: str) -> str:
        """Apply raw YAML content via stdin or tempfile."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name
        try:
            res = self.run(["apply", "-f", temp_path], check=True)
            return res.stdout
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def delete_resource(
        self,
        kind: str,
        name: str,
        namespace: str | None = None,
        *,
        ignore_missing: bool = True,
    ) -> None:
        args = ["delete", kind, name]
        if namespace:
            args.extend(["-n", namespace])
        if ignore_missing:
            args.append("--ignore-not-found=true")
        self.run(args, check=False)

    def get_json(
        self,
        kind: str,
        name: str | None = None,
        namespace: str | None = None,
        label: str | None = None,
    ) -> Any:
        args = ["get", kind]
        if name:
            args.append(name)
        if namespace:
            args.extend(["-n", namespace])
        else:
            args.append("-A")
        if label:
            args.extend(["-l", label])
        args.extend(["-o", "json"])

        res = self.run(args)
        if res.returncode != 0 or not res.stdout.strip():
            return None
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return None

    def current_user(self) -> str:
        """Get current authenticated identity."""
        if Path(self.bin).name == "oc":
            res = self.run(["whoami"])
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        res = self.run(["config", "current-context"])
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
        return "<unknown>"

    def is_openshift(self) -> bool:
        """Check if connected cluster has OpenShift API endpoints."""
        res = self.run(["get", "namespace", "openshift-dns"])
        return res.returncode == 0
