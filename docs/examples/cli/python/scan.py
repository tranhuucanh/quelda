import json
import subprocess
import sys


def quelda_scan(path, policy=None, timeout=30):
    """Scans one file with the quelda CLI. Only exit code 0 means valid."""
    args = ["quelda", "scan", path]
    if policy:
        args += ["--policy", policy]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"valid": False, "status": "TIMEOUT"}
    try:
        verdict = json.loads(r.stdout)
    except ValueError:
        verdict = {"status": f"EXIT {r.returncode}"}
    verdict["valid"] = r.returncode == 0
    return verdict


if __name__ == "__main__":
    v = quelda_scan(sys.argv[1])
    print(f"valid={str(v['valid']).lower()} status={v['status']}")
