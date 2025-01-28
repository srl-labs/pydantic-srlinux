import json

from pydantic_srlinux.models import acl, interfaces

acl_schema = acl.Model().model_json_schema(by_alias=False)
json.dump(acl_schema, open("./schemas/acl_schema.json", "w"), indent=2)

interfaces_schema = interfaces.Model().model_json_schema(by_alias=False)
json.dump(interfaces_schema, open("./schemas/interfaces_schema.json", "w"), indent=2)
