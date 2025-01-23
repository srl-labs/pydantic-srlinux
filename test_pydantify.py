import models.interfaces.out as srl_if

new_if = srl_if.Model(
    interface=[
        srl_if.InterfaceListEntry(
            name="ethernet-1/1",
            admin_state=srl_if.EnumerationEnum.enable,
            description="dan is awesome",
            mtu=9000,
        )
    ]
)


print(new_if.model_dump_json(indent=2, exclude_none=True, exclude_unset=True))
