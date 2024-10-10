""" DHCP Backends """

# flake8: noqa: F401

from dhcp.backends.netbox import NetboxBackend
from dhcp.backends.nautobot import NautobotBackend
from dhcp.backends.base import get_backend
