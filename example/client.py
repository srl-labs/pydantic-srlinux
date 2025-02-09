import datetime
from enum import Enum
from typing import Any, List, Literal, Optional

import httpx
from pydantic import BaseModel

from example.log import logger


class Action(str, Enum):
    REPLACE = "replace"
    UPDATE = "update"
    DELETE = "delete"


class Datastore(str, Enum):
    RUNNING = "running"
    STATE = "state"


class RequestMethod(str, Enum):
    SET = "set"
    GET = "get"


class SetCommand(BaseModel):
    """
    A command structure for the set method.
    """

    action: Action
    path: str
    # value is a json encoded string
    value: Any


class GetCommand(BaseModel):
    """
    A command structure for the get method.
    """

    path: str
    datastore: Datastore


class Params(BaseModel):
    commands: List[SetCommand]


class JsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str
    method: RequestMethod
    params: Params


class SRLClient(httpx.Client):
    def __init__(
        self, host: str, username: str = "admin", password: str = "NokiaSrl1!"
    ):
        super().__init__(verify=False)
        self.base_url: str = f"http://{host}"
        self.jsonrpc_url: str = f"{self.base_url}/jsonrpc"
        self.set_commands: Optional[List[SetCommand]] = []
        self.get_commands: Optional[List[GetCommand]] = []
        self.username: str = username
        self.password: str = password
        self.auth = (self.username, self.password)

    def add_set_command(self, action: Action, path: str, value: BaseModel) -> None:
        """Add command to the set request
        value: srlinux pydantic model to be dumped to json
        """
        cmd = SetCommand(
            action=action,
            path=path,
            value=value.model_dump(
                exclude_none=True,
                exclude_unset=True,
                by_alias=True,
            ),
        )
        if self.set_commands is None:
            self.set_commands = []

        self.set_commands.append(cmd)

    def send_set_request(self) -> httpx.Response:
        """Send set request via JSON RPC"""
        if self.set_commands is None:
            raise ValueError("No commands to send")

        request = JsonRpcRequest(
            id=datetime.datetime.now().isoformat(),
            method=RequestMethod.SET,
            params=Params(commands=self.set_commands),
        )

        response = self.post(url=self.jsonrpc_url, content=request.model_dump_json())

        logger.debug(
            f"send_set_request got response: status={response.status_code} text={response.text}"
        )

        # reset the set commands
        self.set_commands = []

        return response
