"""End-to-end API test script."""
import urllib.request
import json
import time

BASE = "http://127.0.0.1:8000"

# 1. Health check
res = urllib.request.urlopen(BASE + "/health")
print("HEALTH:", json.loads(res.read()))

# 2. Submit code with planted vulnerabilities
code = (
    'password = "s3cr3t"\n'
    'def get_user(username):\n'
    '    return "SELECT * FROM users WHERE name=" + username\n'
)
body = json.dumps({"language": "python", "source": code, "filename": "test.py"}).encode()
req  = urllib.request.Request(
    BASE + "/api/submissions", data=body,
    headers={"Content-Type": "application/json"}, method="POST"
)
res   = urllib.request.urlopen(req)
sub   = json.loads(res.read())
jobId = sub["jobId"]
print("SUBMITTED jobId:", jobId)

# 3. Poll status until done
for i in range(30):
    time.sleep(1)
    res  = urllib.request.urlopen(BASE + f"/api/jobs/{jobId}/status")
    data = json.loads(res.read())
    print(f"  STATUS [{i+1}s]: stage={data['stage']}", data["agents"])
    if data["stage"] == "done":
        break

# 4. Findings
res      = urllib.request.urlopen(BASE + f"/api/jobs/{jobId}/findings")
findings = json.loads(res.read())
print("FINDINGS: healthScore=", findings["healthScore"], "count=", len(findings["findings"]))
for f in findings["findings"][:4]:
    print(" -", f["severity"].upper(), f["title"][:60])

# 5. Assistant
body = json.dumps({"message": "How do I prevent SQL injection?"}).encode()
req  = urllib.request.Request(
    BASE + f"/api/jobs/{jobId}/assistant", data=body,
    headers={"Content-Type": "application/json"}, method="POST"
)
res  = urllib.request.urlopen(req)
chat = json.loads(res.read())
print("ASSISTANT reply:", chat["reply"][:120])
print("SOURCES:", chat.get("sources", [])[:2])

# 6. JSON report
res = urllib.request.urlopen(BASE + f"/api/jobs/{jobId}/report?format=json")
rpt = json.loads(res.read())
print("REPORT job_id:", rpt["job_id"][:8], "  findings:", len(rpt["findings"]))

print("\n=== ALL TESTS PASSED ===")
