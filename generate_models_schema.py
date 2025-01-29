import json

from pydantic_srlinux.models import (
    acl,
    bfd,
    interfaces,
    network_instance,
    platform,
    qos,
    routing_policy,
    system,
    tunnel,
    tunnel_interfaces,
)

mode = "validation"

# ACL
name = "acl"
schema = acl.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# BFD
name = "bfd"
schema = bfd.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# Interfaces
name = "interfaces"
schema = interfaces.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# network instance
name = "network_instance"
schema = network_instance.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# platform
name = "platform"
schema = platform.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# qos
name = "qos"
schema = qos.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# routing policy
name = "routing_policy"
schema = routing_policy.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# system
name = "system"
schema = system.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# tunnel interfaces
name = "tunnel_interfaces"
schema = tunnel_interfaces.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)

# tunnel
name = "tunnel"
schema = tunnel.Model().model_json_schema(by_alias=False, mode=mode)
json.dump(schema, open(f"./schemas/{name}_schema.json", "w"), indent=2)
