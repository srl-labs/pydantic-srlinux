from nornir import InitNornir
from nornir.core import Nornir
from nornir.core.task import Result, Task
from nornir_rich.functions import print_result

from example.client import Action, SRLClient
from example.v4.interface import Interface, Subinterface, Vlan


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


def configure_node(task: Task) -> Result:
    """Configure node task"""
    interface_name = task.host.get("interface_name")
    vlan_id = task.host.get("vlan")

    interface = Interface(name=interface_name)
    subif_100 = Subinterface(index=vlan_id, type="bridged").set_vlan(
        vlan=Vlan(vlan_id=vlan_id)
    )
    interface.add_subif(subif=subif_100)

    # Deploy configuration on a device
    if task.host.hostname is None:
        raise ValueError("hostname must be set")

    with SRLClient(host=task.host.hostname) as client:
        client.add_set_command(
            action=Action.UPDATE,
            path=interface.path,
            value=interface,
        )
        resp = client.send_set_request()

    return Result(
        failed=resp.status_code != 200,
        host=task.host,
        result=interface.to_json(by_alias=False),
    )


def main():
    nr = init_nornir()

    result = nr.run(configure_node)
    print_result(result)


if __name__ == "__main__":
    main()
