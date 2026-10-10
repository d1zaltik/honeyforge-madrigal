import asyncio
import time
import os
import sys
from honeyforge_agent.config import agent_config
from honeyforge_agent.stealth import masquerade_process, calculate_jittered_interval
from honeyforge_agent.buffer import LocalEventBuffer
from honeyforge_agent.sender import TelemetrySender
from honeyforge_agent.honeytokens import HoneytokenManager
from honeyforge_agent.traps.low_interaction import LowInteractionMultiPortTrap
from honeyforge_agent.traps.fake_ssh import FakeSSHTrap
from honeyforge_agent.traps.fake_web import FakeWebTrap

class HoneyForgeAgent:
    """
    Stealth Honeypot Agent Daemon:
    - Runs stealth services (Low/Medium)
    - Persistent store-and-forward buffer (FR-A4)
    - Jittered C2 beacon with encrypted disguised payloads (MASK-1..5)
    """
    def __init__(
        self,
        trap_id: str = None,
        trap_name: str = None,
        secret_key: str = None,
        interaction_level: str = None,
        c2_url: str = None,
        buffer_db_path: str = None,
        ssh_port: int = None,
        web_port: int = None,
        low_ports: list = None
    ):
        self.trap_id = trap_id or agent_config.TRAP_ID
        self.trap_name = trap_name or agent_config.TRAP_NAME
        self.secret_key = secret_key or agent_config.SECRET_KEY
        self.interaction_level = interaction_level or agent_config.INTERACTION_LEVEL
        self.c2_url = c2_url or agent_config.C2_URL
        self.buffer_db_path = buffer_db_path or agent_config.BUFFER_DB_PATH
        self.ssh_port = ssh_port or agent_config.SSH_PORT
        self.web_port = web_port or agent_config.WEB_PORT
        self.low_ports = low_ports or agent_config.LOW_PORTS
        self.proc_name = agent_config.PROC_NAME
        self.beacon_interval = agent_config.BEACON_INTERVAL_S
        self.jitter_pct = agent_config.JITTER_PCT

        self.buffer = LocalEventBuffer(self.buffer_db_path)
        self.sender = TelemetrySender(self.c2_url, self.secret_key, self.trap_id)
        self.honeytokens = HoneytokenManager(self.trap_id, self.c2_url)
        self.start_time = time.time()
        self.traps = []
        self.pending_sessions = []
        self.is_running = False

    def on_attack_event(self, event_dict: dict):
        """Callback from trap listeners: pushes event directly into local buffer"""
        self.buffer.push_event(event_dict)

    def on_session_log(self, session_dict: dict):
        """Callback from interactive shells: buffers full session logs"""
        self.pending_sessions.append(session_dict)

    async def start(self):
        self.is_running = True
        # MASK-4: Obfuscate process title
        masquerade_process(self.proc_name)

        # Plant canary lures (FR-A6)
        self.honeytokens.generate_default_tokens()

        # Initialize traps based on interaction level
        if self.interaction_level in ["low", "all"]:
            low_trap = LowInteractionMultiPortTrap(
                ports=self.low_ports,
                banners={},
                event_callback=self.on_attack_event,
                trap_id=self.trap_id
            )
            await low_trap.start()
            self.traps.append(low_trap)

        if self.interaction_level in ["medium", "all"]:
            ssh_trap = FakeSSHTrap(
                port=self.ssh_port,
                event_callback=self.on_attack_event,
                session_callback=self.on_session_log,
                trap_id=self.trap_id
            )
            await ssh_trap.start()
            self.traps.append(ssh_trap)

            web_trap = FakeWebTrap(
                port=self.web_port,
                event_callback=self.on_attack_event,
                trap_id=self.trap_id
            )
            await web_trap.start()
            self.traps.append(web_trap)

        # Start beacon loop
        asyncio.create_task(self._beacon_loop())

    async def _beacon_loop(self):
        """
        FR-A3, MASK-5:
        Sends telemetry at randomized intervals with jitter and padding.
        Drains local buffer safely when connected.
        """
        while self.is_running:
            try:
                # 1. Prepare Heartbeat
                uptime = int(time.time() - self.start_time)
                heartbeat = {
                    "trap_id": self.trap_id,
                    "uptime_seconds": uptime,
                    "cpu_usage": 2.5,
                    "mem_usage": 6.8,
                    "status": "online",
                    "config_version": 1
                }

                # 2. Extract batch from local buffer (FR-A4)
                pending_events = self.buffer.peek_pending(limit=50)
                sessions_to_send = list(self.pending_sessions)

                # 3. Transmit batch to C2 via disguised endpoint (MASK-2)
                success = await self.sender.send_batch(
                    events=pending_events,
                    session_logs=sessions_to_send,
                    heartbeat_data=heartbeat
                )

                if success:
                    # Clear delivered events from buffer and memory
                    if pending_events:
                        event_ids = [e["event_id"] for e in pending_events if "event_id" in e]
                        self.buffer.mark_delivered(event_ids)
                    self.pending_sessions.clear()

            except Exception:
                pass

            # Calculate next sleep duration with jitter (MASK-5)
            interval = calculate_jittered_interval(self.beacon_interval, self.jitter_pct)
            await asyncio.sleep(interval)

    async def stop(self):
        self.is_running = False
        for t in self.traps:
            await t.stop()

if __name__ == "__main__":
    agent = HoneyForgeAgent()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(agent.start())
        print(f"[*] HoneyForge Agent running ({agent.config.TRAP_ID}) level={agent.config.INTERACTION_LEVEL}")
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(agent.stop())
