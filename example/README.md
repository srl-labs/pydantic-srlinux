# Examples

Deploy the lab with two SR Linux nodes connected to each other with their `ethernet-1/1` interfaces:

```
SRL_VERSION=24.10.2 clab dep -c -t srlinux.dev/clab-srl2
```

You will get nodes `srl1` and `srl2` with no custom configuration deployed. We will use these two nodes throughout the examples.

## Example 3: Abstractions

Revert any changes made to the nodes:

```
bash example/revert.sh
```

To apply the configuration, run:

```
python example/v3/interface.py
```

Run tests as:

```
pytest example/v3/tests/test_interface.py -v
```

## Manually send a payload

> For demo purposes.

```bash
curl 'http://admin:NokiaSrl1!@srl/jsonrpc' -d @- <<EOF | jq
{
    "jsonrpc": "2.0",
    "id": 0,
    "method": "set",
    "params": {
        "commands": [
            {
                "action": "replace",
                "path": "/interface[name=ethernet-1/1]",
                "value": {
                    "srl_nokia-interfaces:name": "ethernet-1/1",
                    "srl_nokia-interfaces:admin-state": "enable",
                    "srl_nokia-interfaces:subinterface": [
                        {
                            "srl_nokia-interfaces:index": 0,
                            "srl_nokia-interfaces:type": "bridged",
                            "srl_nokia-interfaces:admin-state": "enable",
                            "srl_nokia-interfaces-vlans:vlan": {
                                "srl_nokia-interfaces-vlans:encap": {
                                    "srl_nokia-interfaces-vlans:single-tagged": {
                                        "srl_nokia-interfaces-vlans:vlan-id": 100
                                    }
                                }
                            }
                        }
                    ],
                    "srl_nokia-interfaces-vlans:vlan-tagging": true
                }
            }
        ]
    }
}
EOF
```
