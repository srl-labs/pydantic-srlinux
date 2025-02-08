# Example

## Example 3: Abstractions

Run the module as:

```
python -m example.interface_v3
```

Run tests as:

```
pytest example/tests/test_interface_v3.py -v
```

manually sent payload:

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
