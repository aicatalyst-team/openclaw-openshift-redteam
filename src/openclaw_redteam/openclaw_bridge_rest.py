#!/usr/bin/env python3
"""REST bridge: exposes /v1/chat/completions backed by `openclaw agent` CLI.

Runs on the host, kubectl-exec's into the gateway pod, and returns the
agent's response in an OpenAI-compatible JSON envelope that garak understands.

Key fixes over the original:
- Reads session JSONL to extract tool results (payloads are usually empty)
- Clears session files between probes to avoid contamination
- Adds timeout handling for probes that hang (reverse shells, curl timeouts)
- Optional TrustyAI pre-classification via --guardrails-url

Usage:
    export KUBECONFIG=/path/to/kubeconfig
    python openclaw_bridge.py [--port 8111] [--namespace openclaw-gateway] [--agent redteam]

    # With TrustyAI guardrails:
    python openclaw_bridge.py --guardrails-url http://guardrails-orchestrator.openclaw-gateway:8034
"""

import argparse
import json
import subprocess
import sys
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import request as urllib_request
from urllib.error import URLError


def parse_args():
    p = argparse.ArgumentParser(description="OpenClaw REST bridge for garak")
    p.add_argument("--port", type=int, default=8111)
    p.add_argument("--namespace", default="openclaw-gateway")
    p.add_argument("--agent", default="redteam")
    p.add_argument("--timeout", type=int, default=120, help="Timeout for agent CLI call in seconds")
    p.add_argument(
        "--guardrails-url",
        default=None,
        help="URL of fms-guardrails-orchestrator (e.g. http://localhost:8034). "
        "If set, prompts are pre-classified before forwarding to the agent.",
    )
    p.add_argument(
        "--guardrails-threshold",
        type=float,
        default=0.7,
        help="Detection score threshold for guardrails blocking (default: 0.7)",
    )
    return p.parse_args()


ARGS = None
REQUEST_COUNT = 0


def oc_exec(cmd: str, timeout: int = 30) -> str:
    """Run a command inside the gateway pod via oc exec."""
    result = subprocess.run(
        [
            "oc",
            "exec",
            "-n",
            ARGS.namespace,
            "deployment/openclaw",
            "-c",
            "gateway",
            "--",
            "bash",
            "-c",
            cmd,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout


def clear_sessions():
    """Delete session files to prevent contamination between probes."""
    try:
        oc_exec("rm -rf /home/node/.openclaw/agents/{}/sessions/ 2>/dev/null; echo ok".format(ARGS.agent))
    except Exception:
        pass


def extract_tool_results_from_jsonl(jsonl_text: str) -> list[str]:
    """Parse session JSONL and extract all toolResult text entries."""
    results = []
    for line in jsonl_text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            if d.get("type") == "message":
                msg = d["message"]
                role = msg.get("role", "")
                content = msg.get("content", [])

                if role == "toolResult" and isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text = item["text"].strip()
                            # Filter out SSH warnings
                            lines = [l for l in text.split("\n") if not l.startswith("Warning: Permanently added")]
                            filtered = "\n".join(lines).strip()
                            if filtered:
                                results.append(filtered)

                elif role == "assistant" and isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text = item["text"].strip()
                            if text and len(text) > 20:
                                results.append(text)
        except (json.JSONDecodeError, KeyError):
            continue
    return results


def run_agent_probe(prompt: str) -> str:
    """Run a single probe through the OpenClaw agent and extract the response."""
    # Step 1: Clear previous session
    clear_sessions()

    # Step 2: Run the agent with the probe prompt
    try:
        result = subprocess.run(
            [
                "oc",
                "exec",
                "-n",
                ARGS.namespace,
                "deployment/openclaw",
                "-c",
                "gateway",
                "--",
                "node",
                "/app/openclaw.mjs",
                "agent",
                "--agent",
                ARGS.agent,
                "--message",
                prompt,
                "--json",
                "--timeout",
                str(ARGS.timeout),
            ],
            capture_output=True,
            text=True,
            timeout=ARGS.timeout + 30,
        )
        stdout = result.stdout
    except subprocess.TimeoutExpired:
        return "[agent timeout after {}s]".format(ARGS.timeout)

    # Step 3: Try to extract payloads from JSON output first
    text_from_payloads = ""
    try:
        data = json.loads(stdout)
        payloads = data.get("result", {}).get("payloads", [])
        if payloads:
            texts = [p.get("text", "") for p in payloads if p.get("text")]
            text_from_payloads = "\n".join(texts)
    except (json.JSONDecodeError, KeyError):
        pass

    # Step 4: Read session JSONL for tool results (the real content)
    text_from_jsonl = ""
    try:
        jsonl_raw = oc_exec(
            "cat /home/node/.openclaw/agents/{}/sessions/*.jsonl 2>/dev/null".format(ARGS.agent),
            timeout=15,
        )
        if jsonl_raw.strip():
            tool_results = extract_tool_results_from_jsonl(jsonl_raw)
            if tool_results:
                text_from_jsonl = "\n---\n".join(tool_results)
    except (subprocess.TimeoutExpired, Exception):
        pass

    # Step 5: Combine - prefer JSONL (has tool results), fall back to payloads
    if text_from_jsonl:
        return text_from_jsonl
    elif text_from_payloads:
        return text_from_payloads
    else:
        return "[no output captured from agent]"


def check_guardrails(prompt: str) -> tuple[bool, str]:
    """Check prompt against TrustyAI guardrails orchestrator.

    Returns (blocked: bool, reason: str).
    """
    if not ARGS.guardrails_url:
        return False, ""

    url = f"{ARGS.guardrails_url}/api/v2/text/detection/content"
    payload = json.dumps(
        {
            "content": prompt,
            "detectors": {
                "harmful-content": {},
                "prompt-injection": {},
            },
        }
    ).encode()

    req = urllib_request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib_request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            detections = data.get("detections", [])
            for det in detections:
                score = det.get("score", 0)
                detector = det.get("detector_id", "unknown")
                if score >= ARGS.guardrails_threshold:
                    return True, f"Blocked by {detector} (score={score:.2f})"
    except (URLError, json.JSONDecodeError, Exception) as e:
        print(f"[bridge] guardrails check failed: {e}", file=sys.stderr)
        # Don't block on guardrails failure - fail open
        return False, ""

    return False, ""


class BridgeHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        global REQUEST_COUNT

        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return

        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        messages = body.get("messages", [])
        prompt = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")

        if not prompt:
            self.send_error(400, "No user message found")
            return

        REQUEST_COUNT += 1
        req_id = REQUEST_COUNT
        prompt_preview = prompt[:80].replace("\n", "\\n")
        print(f"[bridge] #{req_id} prompt: {prompt_preview}...")

        # Optional TrustyAI guardrails pre-check
        blocked, reason = check_guardrails(prompt)
        if blocked:
            text = f"[BLOCKED BY GUARDRAILS: {reason}]"
            print(f"[bridge] #{req_id} -> {text}")
        else:
            try:
                text = run_agent_probe(prompt)
                preview = text[:120].replace("\n", "\\n")
                print(f"[bridge] #{req_id} -> {preview}...")
            except Exception as e:
                text = f"[bridge error: {e}]"
                print(f"[bridge] #{req_id} ERROR: {e}")
                traceback.print_exc()

        response = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "openclaw-agent",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
        }

        payload = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        """Health check endpoint."""
        if self.path == "/health":
            resp = json.dumps({"status": "ok", "requests": REQUEST_COUNT}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        elif self.path == "/v1/models":
            resp = json.dumps(
                {
                    "data": [{"id": "openclaw-agent", "object": "model"}],
                    "object": "list",
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        # Suppress default HTTP logging (we do our own)
        pass


def main():
    global ARGS
    ARGS = parse_args()

    print(f"[bridge] OpenClaw REST Bridge v2")
    print(f"[bridge] listening on http://127.0.0.1:{ARGS.port}/v1/chat/completions")
    print(f"[bridge] forwarding to: oc exec -n {ARGS.namespace} deployment/openclaw -> agent --agent {ARGS.agent}")
    print(f"[bridge] timeout: {ARGS.timeout}s per probe")
    if ARGS.guardrails_url:
        print(f"[bridge] TrustyAI guardrails: {ARGS.guardrails_url} (threshold={ARGS.guardrails_threshold})")
    else:
        print(f"[bridge] TrustyAI guardrails: disabled")
    print(f"[bridge] ready.")

    server = HTTPServer(("127.0.0.1", ARGS.port), BridgeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[bridge] shutting down after {REQUEST_COUNT} requests")
        server.server_close()


if __name__ == "__main__":
    main()
