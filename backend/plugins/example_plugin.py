PLUGIN_NAME = "Example Plugin"
PLUGIN_DESCRIPTION = "Copy this file to create your own plugin"


def on_network(network: dict) -> dict:
    """
    Called for every discovered network.
    Add new fields to the network dict and return it.
    Whatever keys you add will automatically appear in:
      - The networks table (last columns)
      - The detail drawer
      - The /api/networks response
      - The /api/report export
    Example: network["MyField"] = "some value"
    """
    return network


def on_start():
    """Called when a scan starts. Optional."""
    pass


def on_stop():
    """Called when a scan stops. Optional."""
    pass
