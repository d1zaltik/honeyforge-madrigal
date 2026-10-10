from abc import ABC, abstractmethod
from typing import Callable, Dict, Any

class BaseTrapService(ABC):
    def __init__(self, name: str, port: int, event_callback: Callable[[Dict[str, Any]], None]):
        self.name = name
        self.port = port
        self.event_callback = event_callback
        self.is_running = False

    @abstractmethod
    async def start(self):
        pass

    @abstractmethod
    async def stop(self):
        pass
