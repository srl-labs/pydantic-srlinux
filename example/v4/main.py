from nornir import InitNornir
from nornir.core import Nornir
from nornir.core.task import Result, Task
from nornir_rich.functions import print_result

import pydantic_srlinux.models.network_instance as srl_ni
from example.client import Action, SetCommand, SRLClient
from example.v4.interface import Interface, IPv4, Subinterface
from example.v4.isis import ISISInstance
from example.v4.netinst import NetworkInstance


def init_nornir() -> Nornir:
    """
    Helper function to init the nornir object.
    We could do stuff like setting the default password here
    """
    nr = InitNornir(
        runner={
            "plugin": "threaded",
            "options": {
                "num_workers": 10,
            },
        },
        inventory={
            "plugin": "SimpleInventory",
            "options": {
                "host_file": "example/v4/hosts.yaml",
            },
        },
    )

    return nr


def default_l3_interface(name: str, v4_address: str) -> Interface:
    l3_interface_name = name

    l3_interface = Interface(name=l3_interface_name)

    subif = Subinterface(index=0)
    ipv4 = IPv4(address=v4_address)
    subif.set_ipv4(ipv4=ipv4)

    l3_interface.add_subif(subif=subif)

    return l3_interface


def configure_node(task: Task) -> Result:
    """Configure node task"""

    set_cmds: list[SetCommand] = []

    p2p_interface = default_l3_interface(
        name=task.host.get("p2p_interface").get("name"),
        v4_address=task.host.get("p2p_interface").get("ip"),
    )
    set_cmds.append(
        SetCommand(action=Action.REPLACE, path=p2p_interface.path, value=p2p_interface)
    )

    loopback = default_l3_interface(
        name=task.host.get("loopback").get("name"),
        v4_address=task.host.get("loopback").get("ip"),
    )
    set_cmds.append(
        SetCommand(action=Action.REPLACE, path=loopback.path, value=loopback)
    )

    # Create network instance and attach subinterfaces
    def_net_inst = NetworkInstance(name="default")

    p2p_subif = p2p_interface.get_subif(index=0)
    def_net_inst.add_subif(subif=p2p_subif)
    loopback_subif = loopback.get_subif(index=0)
    def_net_inst.add_subif(subif=loopback_subif)

    set_cmds.append(
        SetCommand(action=Action.UPDATE, path=def_net_inst.path, value=def_net_inst)
    )

    # create isis instance and attach subinterfaces
    isis_inst = ISISInstance(name="isis", net=task.host.get("isis").get("net"))
    isis_inst.add_interface(
        subif=p2p_subif, circuit_type=srl_ni.EnumerationEnum143.point_to_point, level=2
    )
    isis_inst.add_interface(
        subif=loopback_subif,
        level=2,
        passive=True,
    )
    def_net_inst.add_isis_instance(isis_instance=isis_inst)

    # Deploy configuration on a device
    if task.host.hostname is None:
        raise ValueError("hostname must be set")

    with SRLClient(host=task.host.hostname) as client:
        for cmd in set_cmds:
            client.add_set_command(
                action=cmd.action,
                path=cmd.path,
                value=cmd.value,
            )

        resp = client.send_set_request()

        if not resp.json().get("error") and resp.is_success:
            failed = False
            result = [
                cmd.model_dump(exclude_unset=True, exclude_none=True)
                for cmd in set_cmds
            ]
        else:
            failed = True
            result = resp.text

    return Result(
        failed=failed,
        host=task.host,
        result=result,
    )


def main():
    nr = init_nornir()

    result = nr.run(configure_node)
    print_result(result)


if __name__ == "__main__":
    main()
