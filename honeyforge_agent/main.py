import asyncio
import time
import random
import os
import sys
from honeyforge_agent.config import agent_config, DEFAULT_DECOY_CREDENTIALS
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
    - Persistent store-and-forward buffer with deduplication and rotation (FR-A4)
    - Jittered C2 beacon with encrypted disguised payloads and TLS certificate pinning (MASK-1..7)
    - Dynamic runtime configuration synchronization without process restart (FR-A3)
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
        low_ports: list = None,
        persona: dict = None,
        decoy_creds: list = None
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
        self.persona = persona
        self.decoy_creds = decoy_creds if decoy_creds is not None else list(DEFAULT_DECOY_CREDENTIALS)
        self.proc_name = agent_config.PROC_NAME
        self.beacon_interval = agent_config.BEACON_INTERVAL_S
        self.jitter_pct = agent_config.JITTER_PCT
        self.current_config_version = 1

        self.buffer = LocalEventBuffer(self.buffer_db_path)
        self.sender = TelemetrySender(self.c2_url, self.secret_key, self.trap_id)
        self.honeytokens = HoneytokenManager(self.trap_id, self.c2_url)
        self.start_time = time.time()
        self.traps = []
        self.ssh_trap_instance = None
        self.pending_sessions = []
        self.is_running = False

    def on_attack_event(self, event_dict: dict):
        """Callback from trap listeners: pushes event directly into local buffer and triggers immediate flush"""
        if "captured_at" not in event_dict:
            event_dict["captured_at"] = time.time()
        self.buffer.push_event(event_dict)
        if hasattr(self, '_flush_event') and self._flush_event:
            if hasattr(self, 'loop') and self.loop and self.loop.is_running():
                self.loop.call_soon_threadsafe(self._flush_event.set)
            else:
                self._flush_event.set()

    def on_session_log(self, session_dict: dict):
        """Callback from interactive shells: buffers full session logs and triggers immediate flush"""
        self.pending_sessions.append(session_dict)
        if hasattr(self, '_flush_event') and self._flush_event:
            if hasattr(self, 'loop') and self.loop and self.loop.is_running():
                self.loop.call_soon_threadsafe(self._flush_event.set)
            else:
                self._flush_event.set()

    async def start(self):
        self.is_running = True
        self.loop = asyncio.get_running_loop()
        self._flush_event = asyncio.Event()

        # MASK-4: Obfuscate process title
        masquerade_process(self.proc_name)

        # Plant canary lures (FR-A6)
        self.honeytokens.generate_default_tokens()

        # Initialize traps based on interaction level
        if self.interaction_level in ["low", "all"]:
            self.low_trap_instance = LowInteractionMultiPortTrap(
                ports=self.low_ports,
                banners={},
                event_callback=self.on_attack_event,
                trap_id=self.trap_id,
                persona=self.persona
            )
            await self.low_trap_instance.start()
            self.traps.append(self.low_trap_instance)

        if self.interaction_level in ["medium", "all"]:
            self.ssh_trap_instance = FakeSSHTrap(
                port=self.ssh_port,
                event_callback=self.on_attack_event,
                session_callback=self.on_session_log,
                trap_id=self.trap_id,
                decoy_creds=self.decoy_creds,
                persona=self.persona
            )
            await self.ssh_trap_instance.start()
            self.traps.append(self.ssh_trap_instance)

            self.web_trap_instance = FakeWebTrap(
                port=self.web_port,
                event_callback=self.on_attack_event,
                trap_id=self.trap_id,
                persona=self.persona
            )
            await self.web_trap_instance.start()
            self.traps.append(self.web_trap_instance)

        # Start beacon loop and runtime config polling loop
        asyncio.create_task(self._beacon_loop())
        asyncio.create_task(self._config_poll_loop())

    async def _config_poll_loop(self):
        """
        FR-A3: Dynamic runtime configuration synchronization.
        Periodically queries upstream C2 for updated decoy credentials, persona, and parameters,
        applying changes dynamically without dropping service or restarting processes.
        """
        while self.is_running:
            await asyncio.sleep(30.0)
            try:
                cfg = await self.sender.fetch_config()
                if cfg:
                    new_version = cfg.get("config_version", self.current_config_version)
                    if new_version > self.current_config_version:
                        self.current_config_version = new_version
                        new_creds = cfg.get("decoy_credentials")
                        new_persona = cfg.get("persona")
                        new_banners = cfg.get("banners")

                        # Dynamic update of fake SSH trap credentials & persona
                        if self.ssh_trap_instance:
                            self.ssh_trap_instance.update_config(decoy_creds=new_creds, persona=new_persona)

                        # Dynamic update of fake Web trap persona
                        if getattr(self, "web_trap_instance", None):
                            self.web_trap_instance.update_config(persona=new_persona)

                        # Dynamic update of low interaction trap persona & banners
                        if getattr(self, "low_trap_instance", None):
                            self.low_trap_instance.update_config(persona=new_persona, banners=new_banners)

                        # Update stealth parameters
                        stealth_p = cfg.get("stealth", {})
                        if "beacon_interval_s" in stealth_p:
                            self.beacon_interval = float(stealth_p["beacon_interval_s"])
                        if "jitter_pct" in stealth_p:
                            self.jitter_pct = float(stealth_p["jitter_pct"])

                        # Acknowledge rotation if secret key changed
                        if "secret_key" in cfg and cfg["secret_key"] != self.secret_key:
                            self.secret_key = cfg["secret_key"]
                            self.sender.secret_key = self.secret_key
                            await self.sender.confirm_credential_rotation()
            except Exception:
                pass

    async def _beacon_loop(self):
        """
        FR-A3, MASK-5, FR-A4:
        Sends telemetry at randomized intervals with jitter and padding,
        or immediately upon receiving real attack telemetry.
        Drains local buffer safely when connected, applying exponential backoff on failure.
        """
        while self.is_running:
            try:
                # 1. Prepare Heartbeat
                uptime = int(time.time() - self.start_time)
                heartbeat = {
                    "trap_id": self.trap_id,
                    "uptime_seconds": uptime,
                    "cpu_usage": round(random.uniform(1.5, 7.8), 1),
                    "mem_usage": round(random.uniform(4.2, 11.5), 1),
                    "status": "online",
                    "config_version": self.current_config_version
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
                    self.buffer.record_success()
                    if pending_events:
                        event_ids = [e["event_id"] for e in pending_events if "event_id" in e]
                        self.buffer.mark_delivered(event_ids)
                    self.pending_sessions.clear()
                else:
                    self.buffer.record_failure()

            except Exception:
                self.buffer.record_failure()

            # Calculate next sleep duration with jitter (MASK-5), applying backoff if in failure state
            interval = calculate_jittered_interval(self.beacon_interval, self.jitter_pct)
            backoff = self.buffer.get_backoff_delay(max_delay=15.0)
            sleep_duration = max(interval, backoff) if backoff > 0 else interval

            # Wake early if attack occurs (_flush_event)
            try:
                await asyncio.wait_for(self._flush_event.wait(), timeout=sleep_duration)
                self._flush_event.clear()
            except asyncio.TimeoutError:
                pass

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
        print(f"[*] HoneyForge Agent running ({agent.trap_id}) level={agent.interaction_level}")
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(agent.stop())
