import subprocess
import re

def get_diff():
    """Fetch git diff for the current PR."""
    result = subprocess.run(["git", "diff", "origin/main...HEAD"], capture_output=True, text=True)
    return result.stdout

def scan_vulnerabilities(diff):
    findings = []

    # Example vulnerability patterns (you can expand these)
    rules = {
        "API Key": r"['\"](AKIA|AIza|ghp_)[0-9A-Za-z]{10,}['\"]",
        "SQL Injection": r"SELECT\s+\*\s+FROM|INSERT\s+INTO|DROP\s+TABLE",
        "Hardcoded Password": r"password\s*=\s*['\"].+['\"]"
    }

    for name, pattern in rules.items():
        matches = re.findall(pattern, diff, re.IGNORECASE)
        if matches:
            findings.append(f"{name} detected {len(matches)} time(s)")

    return findings

def main():
    diff = get_diff()
    findings = scan_vulnerabilities(diff)

    if findings:
        print("⚠️ Vulnerabilities found:")
        for f in findings:
            print(f" - {f}")
    else:
        print("✅ No vulnerabilities found.")

if __name__ == "__main__":
    main()
