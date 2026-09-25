from abc import ABC, abstractmethod
from ..core.http_client import HTTPClient
from ..core.reporter import Reporter


class BaseModule(ABC):
    name = "base"
    description = "Base module"

    def __init__(self, http: HTTPClient, reporter: Reporter):
        self.http = http
        self.reporter = reporter

    @abstractmethod
    def run(self, url: str, params: dict = None):
        pass

    def log(self, msg: str):
        print(f"  [{self.name}] {msg}")
