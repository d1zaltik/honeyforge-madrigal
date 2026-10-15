import urllib.request
import json

__test__ = False

def run_sim(scenario):
    data = json.dumps({"scenario": scenario}).encode()
    req = urllib.request.Request(
        "http://localhost:8000/api/v1/simulator/run",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"[{scenario}] status={resp.status} response={resp.read().decode()}")

if __name__ == "__main__":
    for s in ["port_scan", "ssh_brute_force", "post_exploitation", "honeytoken_breach"]:
        run_sim(s)

