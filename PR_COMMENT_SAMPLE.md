# RepoGuard-AI PR Comment Sample

When the scanner finds issues, it posts a PR comment with a short summary and findings.

Example (structured JSON output saved as repoguard_results.json):

```
[
  {
    "file": "app/controllers/user_controller.py",
    "line": 42,
    "vulnerability_type": "sqli",
    "suggestion": "Use parameterized queries instead of string formatting."
  },
  {
    "file": "config/credentials.txt",
    "line": 1,
    "vulnerability_type": "secret/credential",
    "suggestion": "Remove secret from repo and store in secrets manager; rotate credentials." 
  }
]
```

The GitHub PR comment body looks like:

## RepoGuard-AI findings
The scanner found the following potential issues:

- **sqli** in `app/controllers/user_controller.py` at line 42: Use parameterized queries instead of string formatting.
- **secret/credential** in `config/credentials.txt` at line 1: Remove secret from repo and store in secrets manager; rotate credentials.

> This comment was generated automatically by RepoGuard-AI.
