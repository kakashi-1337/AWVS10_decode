"""
JS Worker Runner - spawns Node.js subprocesses for JS analysis tasks.
Wraps genki-prober (IAST, JS analysis, deobfuscation) and
kiseichu (fuzzer, DOM invader, mutation engine).
"""
import json
import subprocess
import os
from pathlib import Path

WORKERS_DIR = Path(__file__).parent


def run_js_worker(script_name, args=None, input_data=None, timeout=60):
    """Run a JS worker script via Node.js subprocess."""
    script_path = WORKERS_DIR / script_name
    if not script_path.exists():
        raise FileNotFoundError(f"JS worker not found: {script_name}")

    cmd = ["node", str(script_path)]
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout,
            input=json.dumps(input_data) if input_data else None,
            cwd=str(WORKERS_DIR),
        )
        if result.returncode != 0:
            return {"error": result.stderr[:500], "stdout": result.stdout[:500]}

        # Try to parse JSON output
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw_output": result.stdout[:2000]}
    except subprocess.TimeoutExpired:
        return {"error": f"Worker timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": "Node.js not installed"}


def run_js_analyzer(js_source_code):
    """Analyze JavaScript source for endpoints, secrets, and interesting patterns."""
    return run_js_worker("js-analyzer.cjs", input_data={"source": js_source_code})


def run_js_deobfuscator(obfuscated_js):
    """Attempt to deobfuscate JavaScript code."""
    return run_js_worker("js-deobfuscator.cjs", input_data={"source": obfuscated_js})


def run_script_harvester(url, html_content):
    """Extract and analyze all script tags from HTML."""
    return run_js_worker("script-harvester.cjs", input_data={"url": url, "html": html_content})
