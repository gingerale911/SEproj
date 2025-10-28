# RepoGuard-AI

RepoGuard-AI is a lightweight starter tool that scans changed code (via git diffs) using an LLM
and optional TruffleHog pre-scan to detect common security issues (SQL injection, secrets, XSS,
and prompt injection). It is intended to run as a GitHub Action but can also be run locally.

Quick start (local)

1. Create a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the scanner in a git checkout (defaults to `repoguard.yml`):

```bash
python repoguard.py --config repoguard.yml
```

Smoke test

There is a minimal smoke test at `tests/smoke_test.py` that creates a temporary git repo with a
sample vulnerable change and runs the scanner to verify end-to-end behavior.

```bash
python tests/smoke_test.py
```

Configuration

Edit `repoguard.yml` to enable/disable checks (sqli, secrets, xss, prompt_injection), and to set
`llm_endpoint` or the `model` name. If using OpenAI, set `OPENAI_API_KEY` in the environment.

GitHub Actions

The included workflow `.github/workflows/repoguard.yml` installs Python, runs the scanner and uploads
`repoguard_results.json` as an artifact. To post PR comments the Action uses the built-in `GITHUB_TOKEN`.

Notes & next steps

- The RAG retrieval is a simple keyword heuristic to avoid sending the entire repo to the LLM.
- For higher accuracy you can plug in embedding-based retrieval (FAISS/Annoy + OpenAI embeddings).
- Use function-calling or stricter JSON enforcement for the LLM to improve parsing reliability.
