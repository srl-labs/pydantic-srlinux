import models.interfaces.out as srl_if

new_if = srl_if.Model(
    interface=[
        srl_if.InterfaceListEntry(
            name="test123",
            # description=srl_if.DescriptionLeaf(
            #     srl_if.DescriptionType("my description")
            # ),
        )
    ]
)

print(new_if.model_dump_json())
