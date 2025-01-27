import logging
from typing import Any, List, Literal, Optional

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class Command(BaseModel):
    action: Literal["update", "replace", "delete"] | None = None
    path: str
    # value is a json encoded string
    value: Any


class Params(BaseModel):
    commands: List[Command]


class JsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: int
    method: Literal["get", "set", "validate"]
    params: Params


class SRLClient(httpx.Client):
    def __init__(
        self, host: str, username: str = "admin", password: str = "NokiaSrl1!"
    ):
        super().__init__(verify=False)
        self.base_url: str = f"http://{host}"
        self.jsonrpc_url: str = f"{self.base_url}/jsonrpc"
        self.commands: Optional[List[Command]] = []
        self.username: str = username
        self.password: str = password
        self.req_id: int = 0
        self.auth = (self.username, self.password)

    def add_command(self, command: Command) -> None:
        """Add command to request"""
        if self.commands is None:
            self.commands = []

        self.commands.append(command)

    def send_request(self) -> httpx.Response:
        """Send request via JSON RPC"""
        if self.commands is None:
            raise ValueError("No commands to send")

        self.req_id = self.req_id + 1
        request = JsonRpcRequest(
            id=self.req_id,
            method="set",
            params=Params(commands=self.commands),
        )

        print(request.model_dump_json())

        response = self.post(url=self.jsonrpc_url, content=request.model_dump_json())

        print(response.json())

        return response
