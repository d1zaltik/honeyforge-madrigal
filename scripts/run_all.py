import asyncio
import sys
import os
import signal
import uvicorn

if sys.platform.startswith("win"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add workspace to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from honeyforge_server.app.main import app
from honeyforge_agent.main import HoneyForgeAgent
from honeyforge_agent.config import agent_config

async def run_platform():
    print("""
======================================================================
  🛡️  HONEYFORGE PLATFORM ALL-IN-ONE STANDALONE RUNNER  🛡️
======================================================================
  [+] C2 Web-UI Dashboard : http://localhost:8000
  [+] Disguised Telemetry  : http://localhost:8000/v1/telemetry/collect
  [+] Low-Interaction Trap: Ports 2121 (FTP), 2323 (Telnet), 6379 (Redis)
  [+] Medium Trap (SSH)   : Port 2222 (root:admin123)
  [+] Medium Trap (Web)   : Port 8088 (http://localhost:8088)
======================================================================
    """)

    # 1. Start C2 Server with Uvicorn in background task
    config = uvicorn.Config(app=app, host="0.0.0.0", port=8000, log_level="warning")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    # Wait for C2 to be ready
    await asyncio.sleep(1.5)

    # 2. Start Agent 1: Low-Interaction Perimeter Trap
    agent_low = HoneyForgeAgent(
        trap_id="trap-low-01",
        trap_name="DMZ-Perimeter-Trap-01",
        secret_key="secret-key-low-01",
        interaction_level="low",
        buffer_db_path=".trap_low.store.db",
        low_ports=[2121, 2323, 6379]
    )
    await agent_low.start()
    print("[*] Trap 'trap-low-01' (Low Interaction) started.")

    # 3. Start Agent 2: Medium-Interaction SSH & Web Trap
    agent_med = HoneyForgeAgent(
        trap_id="trap-med-01",
        trap_name="Internal-SSH-Trap-02",
        secret_key="secret-key-med-01",
        interaction_level="medium",
        buffer_db_path=".trap_med.store.db",
        ssh_port=2222,
        web_port=8088
    )
    await agent_med.start()
    print("[*] Trap 'trap-med-01' (Medium Interaction SSH+Web) started.")

    print("\n[✔] ALL HONEYFORGE SERVICES ACTIVE! Press Ctrl+C to terminate.\n")

    try:
        await server_task
    except asyncio.CancelledError:
        pass
    finally:
        await agent_low.stop()
        await agent_med.stop()
        await server.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(run_platform())
    except KeyboardInterrupt:
        print("\n[*] Shutting down HoneyForge platform...")
