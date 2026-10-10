import asyncio
import uuid
import datetime
from typing import Dict, Any, Callable
from honeyforge_agent.traps.base import BaseTrapService

DEFAULT_BANNERS = {
    2121: b"220 ProFTPD 1.3.5 Server (Ubuntu) [10.0.1.5]\r\n",
    2323: b"Ubuntu 22.04 LTS\r\nlogin: ",
    6379: b"-ERR operation not permitted\r\n"
}

SERVICE_NAMES = {
    2121: "FTP",
    2323: "Telnet",
    6379: "Redis"
}

class LowInteractionMultiPortTrap(BaseTrapService):
    """
    FR-A1 (Must): Low-interaction multi-port trap.
    Emulates open service ports and realistic banners (TCP), collecting scanner and probe metadata.
    """
    def __init__(self, ports: list, banners: dict, event_callback: Callable[[Dict[str, Any]], None], trap_id: str):
        super().__init__("LowInteractionPerimeter", 0, event_callback)
        self.ports = ports
        self.banners = {int(p): b.encode() if isinstance(b, str) else b for p, b in banners.items()} if banners else DEFAULT_BANNERS
        self.trap_id = trap_id
        self.servers = []

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
        peer = writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "0.0.0.0"
        client_port = peer[1] if peer else 0
        protocol_name = SERVICE_NAMES.get(port, f"TCP-{port}")
        
        banner = self.banners.get(port, DEFAULT_BANNERS.get(port, b"220 Service Ready\r\n"))
        
        try:
            # Send authentic banner (MASK-6: realistic banner)
            writer.write(banner)
            await writer.drain()

            # Read initial probe bytes from attacker
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=3.0)
            except asyncio.TimeoutError:
                pass

            payload_repr = data.decode(errors="ignore").strip() if data else "SYN/ACK Handshake"
            
            # Emit attack event
            event = {
                "event_id": str(uuid.uuid4()),
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source_ip": client_ip,
                "source_port": client_port,
                "protocol": protocol_name,
                "destination_port": port,
                "event_type": "port_scan" if not data else "banner_probe",
                "severity": "low" if not data else "medium",
                "payload_raw": payload_repr[:200],
                "is_ioc": False
            }
            self.event_callback(event)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.is_running = True
        for port in self.ports:
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port: self._handle_connection(r, w, p),
                    "0.0.0.0",
                    port
                )
                self.servers.append(server)
            except Exception as e:
                pass

    async def stop(self):
        self.is_running = False
        for s in self.servers:
            s.close()
            await s.wait_closed()
        self.servers.clear()
