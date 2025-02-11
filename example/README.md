# Examples

The examples in this repository show how one could use the pydantify-generated pydantic models. Starting from the most simple example and building up to more complex and feature-rich ones.

Roman goes over these examples in the following video:

[![yt](https://gitlab.com/rdodin/pics/-/wikis/uploads/50cdfddb1e35ad11c1b6836436bcfc85/netrel016-iterate-pydantify-yt.png)](https://youtu.be/CM3sT55zwt0)

To run the demos install the demo dependencies:

```
uv sync --all-groups
```

Deploy the lab with two SR Linux nodes connected to each other with their `ethernet-1/1` interfaces:

```
SRL_VERSION=24.10.2 clab dep -c -t srlinux.dev/clab-srl2
```

You will get nodes `srl1` and `srl2` with no custom configuration deployed. We will use these two nodes throughout the examples.

Before each new example, revert the lab nodes to the initial state:

```
bash example/revert.sh
```

## Example 1: Basics

Example 1 in the [v1 dir](v1) shows a basic usage of pydantic models generated with pydantify. It creates an interface with a subinterface and a single tagged VLAN all in one statement.

## Example 2: Decomposition

Example 2 in the [v2 dir](v2) builds on top of example 1 and instead of using a single statement to create interface, subinterface and vlan objects, it uses a separate function to create the subinterface with VLAN object.

This decomposes the large configuration task into smaller chunks making it easier to read and maintain.

## Example 3: Abstractions

Example 2 in the [v3 dir](v3) introduces custom classes for interfaces, subinterfaces and vlans. The custom classes are subclasses of the relevant pydantic classes, but with additional methods that allow to build relationship between the objects.

For instance, the Interface class has a method `add_subif` that takes in a Subinterface object and adds it to the list of subinterfaces this Interface maintains.

Using classes and methods help to further parametrize the task of building the objects and relationships between them.

To apply the configuration, run:

```
python example/v3/interface.py
```

This examples demonstrates the pytest-based tests. You can run the tests with:

```
pytest example/v3/tests/test_interface.py -v
```

## Example 4: Concurrent configuration with Nornir

Taking it one step further, we can use Nornir to configure the nodes concurrently, while enjoying the full python experience.

This examples configures the ISIS between the two nodes and exchanges loopback prefixes to achieve connectivity between them.

To apply the configuration, run:

```
python example/v4/main.py
```

You will find the nornir inventory in the `example/v4/hosts.yaml` file.
