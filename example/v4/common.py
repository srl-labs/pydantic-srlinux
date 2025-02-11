from pydantic import BaseModel


class ConfigObject(BaseModel):
    """Class with the common methods for SR Linux models"""

    def to_json(self, by_alias: bool) -> str:
        return self.model_dump_json(
            exclude_none=True,
            exclude_unset=True,
            by_alias=by_alias,
            indent=2,
        )
