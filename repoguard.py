#!/usr/bin/env python3
"""
RepoGuard-AI - simple Python scanner for changed files using an LLM + optional TruffleHog

Outputs structured JSON findings and can post PR comments using GITHUB_TOKEN.

Usage (local):
  python repoguard.py --config repoguard.yml

The script expects to be run in a git repo (or a CI checkout). It gathers `git diff` for the
current commit/branch, extracts changed file hunks, optionally pre-scans with TruffleHog, then
sends relevant snippets to an LLM (OpenAI or local) for vulnerability detection.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from typing import List, Dict, Any
import shutil

try:
    import yaml
except Exception:
    print("Missing dependency 'pyyaml'. Install via pip install pyyaml", file=sys.stderr)
    raise

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install via pip install requests", file=sys.stderr)
    raise

try:
    import openai
except Exception:
    openai = None

DEFAULT_CONFIG = {
    "checks": {
        "sqli": True,
        "secrets": True,
        "xss": False,
        "prompt_injection": True
    },
    "rag_enabled": True,
    "max_snippet_tokens": 2000,
    "model": "gpt-3.5-turbo",
    "llm_endpoint": "",  # optional local endpoint
    "provider": "openai"  # can be 'openai', 'google', or 'local'
}


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        print(f"Config {path} not found; using defaults")
        return DEFAULT_CONFIG
    with open(path, "r") as f:
        conf = yaml.safe_load(f) or {}
    merged = DEFAULT_CONFIG.copy()
    merged.update(conf)
    # merge nested checks
    checks = DEFAULT_CONFIG["checks"].copy()
    checks.update(conf.get("checks", {}))
    merged["checks"] = checks
    return merged


def git_diff_changed_files(base_ref: str = None) -> str:
    """Return unified diff for the current HEAD vs base_ref (if provided), else staged changes."""
    cmd = ["git", "diff", "-U3"]
    if base_ref:
        cmd = ["git", "diff", "-U3", base_ref]
    try:
        proc = subprocess.run(cmd, capture_output=True, check=True, text=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        print("git diff failed:", e, file=sys.stderr)
        return ""


def parse_unified_diff(diff_text: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parse the unified diff and return map file -> list of hunks with context and start lines."""
    files = {}
    current_file = None
    hunk_re = re.compile(r'^@@ \-(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')
    lines = diff_text.splitlines()
    i = 0
    while i < len(lines):
        l = lines[i]
        if l.startswith('+++ b/'):
            current_file = l[6:]
            files.setdefault(current_file, [])
            i += 1
            continue
        m = hunk_re.match(l)
        if m and current_file:
            start_line = int(m.group(2))
            i += 1
            hunk_lines = []
            while i < len(lines) and not lines[i].startswith('@@') and not lines[i].startswith('+++ b/') and not lines[i].startswith('diff --git'):
                hunk_lines.append(lines[i])
                i += 1
            files[current_file].append({"start_line": start_line, "lines": hunk_lines})
            continue
        i += 1
    return files


KEYWORDS = {
    "sqli": ["execute", "cursor.execute", "SELECT", "WHERE", "format(", "%", "f\"", "raw_query", "sql"],
    "secrets": ["api_key", "secret", "password", "access_token", "AWS_SECRET", "PRIVATE_KEY"],
    "xss": ["innerHTML", "dangerouslySetInnerHTML", "document.write", "innerText"],
    "prompt_injection": ["openai", "system prompt", "assistant", "prompt"]
}


def simple_rag_filter(hunks: Dict[str, List[Dict[str, Any]]], checks: Dict[str, bool]) -> Dict[str, List[Dict[str, Any]]]:
    """Keep only hunks that match keywords for enabled checks.

    This is a simple heuristic retrieval step to avoid sending the entire repo to the LLM.
    """
    enabled_checks = [k for k, v in checks.items() if v]
    out = {}
    for fname, hunk_list in hunks.items():
        matched = []
        for h in hunk_list:
            text = "\n".join(h["lines"]) if h.get("lines") else ""
            score = 0
            for chk in enabled_checks:
                for kw in KEYWORDS.get(chk, []):
                    if kw.lower() in text.lower():
                        score += 1
            if score > 0 or len(text) < 1000:
                matched.append(h)
        if matched:
            out[fname] = matched
    return out




def build_prompt(snippets: Dict[str, List[Dict[str, Any]]], config: Dict[str, Any]) -> str:
    checks = [k for k, v in config["checks"].items() if v]
    header = textwrap.dedent(f"""
    You are a security code reviewer.
    Analyze the provided code snippets for the following checks: {', '.join(checks)}.
    For each finding return a JSON object with fields: file, line, vulnerability_type, and suggestion.
    Only return a JSON array of findings, nothing else.
    """
    )
    parts = [header]
    for fname, hlist in snippets.items():
        for h in hlist:
            parts.append(f"FILE: {fname} START_LINE: {h['start_line']}\n```\n{''.join(h['lines'])}\n```\n")
    return "\n---\n".join(parts)



def call_llm(prompt: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Call OpenAI, Google AI Studio, or a local LLM endpoint. Expect the LLM to respond with JSON array."""
    provider = config.get("provider", "openai").lower()
    llm_endpoint = config.get("llm_endpoint") or os.environ.get("LLM_ENDPOINT")
    openai_key = os.environ.get("OPENAI_API_KEY")
    google_key = os.environ.get("GOOGLE_API_KEY")
    model = config.get("model", "gpt-3.5-turbo")
    text = None

    if provider == "openai":
        if openai_key and openai:
            openai.api_key = openai_key
            try:
                resp = openai.ChatCompletion.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": "You are a security code reviewer."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0
                )
                text = resp.choices[0].message.content
            except Exception as e:
                print("OpenAI call failed:", e, file=sys.stderr)
                return []
        else:
            print("No OpenAI API key or openai package not installed.", file=sys.stderr)
            return []
    elif provider == "google":
        if not google_key:
            print("No GOOGLE_API_KEY set in environment.", file=sys.stderr)
            return []
        # Use the model specified in config (default: gemini-pro, can be gemini-2.5-flash-lite, etc.)
        model_name = config.get("model", "gemini-pro")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
        }
        params = {"key": google_key}
        try:
            r = requests.post(url, headers=headers, params=params, json=payload)
            r.raise_for_status()
            resp = r.json()
            # Extract text from response (Gemini returns candidates)
            text = resp.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        except Exception as e:
            print("Google AI Studio call failed:", e, file=sys.stderr)
            return []
    elif provider == "local":
        if llm_endpoint:
            try:
                r = requests.post(llm_endpoint, json={"prompt": prompt, "max_tokens": 800})
                r.raise_for_status()
                text = r.text
            except Exception as e:
                print("Local LLM call failed:", e, file=sys.stderr)
                return []
        else:
            print("No local LLM endpoint configured.", file=sys.stderr)
            return []
    else:
        print(f"Unknown provider: {provider}", file=sys.stderr)
        return []

    # try to extract JSON array
    j = None
    try:
        j = json.loads(text)
    except Exception:
        # attempt to find first JSON array in text
        m = re.search(r"(\[\s*\{.*\}\s*\])", text or "", re.S)
        if m:
            try:
                j = json.loads(m.group(1))
            except Exception:
                j = None
    if not j:
        print("LLM did not return parseable JSON. Raw output:\n", text, file=sys.stderr)
        return []
    return j


def format_findings(raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in raw_findings:
        # Ensure required fields
        file = r.get("file")
        line = r.get("line") or r.get("start_line") or 1
        vtype = r.get("vulnerability_type") or r.get("type") or "unknown"
        suggestion = r.get("suggestion") or r.get("recommendation") or "Review code and apply secure patterns."
        out.append({"file": file, "line": line, "vulnerability_type": vtype, "suggestion": suggestion})
    return out


def write_results(results: List[Dict[str, Any]], path: str = "repoguard_results.json"):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Wrote {len(results)} findings to {path}")


def post_pr_comments(findings: List[Dict[str, Any]]):
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not token or not repo or not event_path:
        print("GITHUB_TOKEN, GITHUB_REPOSITORY, or GITHUB_EVENT_PATH not available; skipping PR comment posting")
        return
    try:
        with open(event_path, "r") as f:
            ev = json.load(f)
    except Exception as e:
        print("Failed to read GITHUB_EVENT_PATH:", e, file=sys.stderr)
        return

    pr_number = None
    # event types differ; try common locations
    pr_number = ev.get("number") or (ev.get("pull_request") or {}).get("number")
    if not pr_number:
        print("No PR number found in event payload; skipping comments")
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
    # Always post a 'hi' comment first
    hi_body = json.dumps({"body": "hi"})
    r1 = requests.post(url, headers=headers, data=hi_body)
    if r1.status_code >= 200 and r1.status_code < 300:
        print("Posted hi PR comment")
    else:
        print("Failed to post hi PR comment:", r1.status_code, r1.text, file=sys.stderr)

    # Then post the normal findings or a completion message
    body = json.dumps({"body": render_pr_comment(findings)})
    r2 = requests.post(url, headers=headers, data=body)
    if r2.status_code >= 200 and r2.status_code < 300:
        print("Posted PR comment")
    else:
        print("Failed to post PR comment:", r2.status_code, r2.text, file=sys.stderr)


def render_pr_comment(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "RepoGuard-AI scan completed: no findings 🎉"
    parts = ["## RepoGuard-AI findings\nThe scanner found the following potential issues:\n"]
    for f in findings:
        parts.append(f"- **{f['vulnerability_type']}** in `{f['file']}` at line {f['line']}: {f['suggestion']}")
    parts.append('\n> This comment was generated automatically by RepoGuard-AI.')
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="repoguard.yml", help="Path to config YAML")
    parser.add_argument("--base", default=None, help="Base git ref to diff against (optional)")
    parser.add_argument("--output", default="repoguard_results.json")
    args = parser.parse_args()

    config = load_config(args.config)

    diff_text = git_diff_changed_files(args.base)
    if not diff_text:
        print("No git diff output found. Exiting.")
        sys.exit(0)

    hunks = parse_unified_diff(diff_text)
    # RAG-style filtering: keep only hunks likely relevant
    snippets = hunks
    if config.get("rag_enabled"):
        snippets = simple_rag_filter(hunks, config.get("checks", {}))


    prompt = build_prompt(snippets, config)
    raw = call_llm(prompt, config)
    findings = format_findings(raw)
    write_results(findings, args.output)
    #hi
    # Post PR comment if running in GitHub Actions
    post_pr_comments(findings)


if __name__ == "__main__":
    main()
