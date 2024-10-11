""" Nautobot DHCP backend """

import os
import logging
import ipaddress
from datetime import datetime, timedelta, timezone

from dhcp.backends.base import DHCPBackend
from dhcp.lease import Lease
from dhcp.packet import PacketOption
from dhcp.settings import SETTINGS
from dhcp.packet import Packet

logger = logging.getLogger(__name__)

# Names of Nautobot IP Address custom fields where we store DHCP Lease metadata
NAUTOBOT_CUSTOM_FIELDS = {"pydhcp_expire", "pydhcp_mac", "pydhcp_hostname"}

# We will only operate on networks that have one of these roles:
PREFIX_DHCP_ROLE = ["Server BMC"]

# Type of dynamically-created IP Address objects in Nautobot
IPADDRESS_DHCP_TYPE = "dhcp"

# DHCP scope excludes the first 5 ips in subnet, and excludes broadcast
DHCP_POOL_SLICE = slice(5, -1)

# The offset from the start of the subnet of the IP used for default gateway
GATEWAY_INDEX = 1

class NautobotBackend(DHCPBackend):
    """ Manage DHCP leases using Nautobot as source of truth

    This was based on the Netbox backend and updated to reflect how the Nautobot
    API is different from Netbox.  I also changed the IP allocation strategy:
    the Netbox backend required that the DHCP "scope" IP addresses and the
    "default gateway" for the subnet be defined by creating IP Addresses in
    Nautobot.   I made these items implicit, so the IP will be created
    automatically following rackspace IP assignment conventions.
    """

    NAME = "nautobot"

    def __init__(self, url=None, token=None, allow_unknown_devices=False, lease_time=None):
        self.url = url or SETTINGS.nautobot_url or os.getenv("NAUTOBOT_URL", None)
        self.token = token or SETTINGS.nautobot_token or os.getenv("NAUTOBOT_TOKEN", None)
        self.lease_time = lease_time or SETTINGS.lease_time or \
            int(os.getenv("PYDHCP_LEASE_TIME", "3600"))
        self.allow_unknown_devices = allow_unknown_devices or \
            SETTINGS.nautobot_allow_unknown_devices or \
            os.getenv("NAUTOBOT_ALLOW_UNKNOWN_DEVICES", "false").lower() == "true"

        if not self.url:
            raise RuntimeError("url required for nautobot backend")

        if not self.token:
            raise RuntimeError("token required for nautobot backend")

        self.client = pynautobot.api(self.url, self.token)
        self.nautobot_setup()


    def nautobot_setup(self):
        """Make sure Nautobot instance has all our pre-requiste objects"""
        fields_already_present = {
            f.label for f in self.client.extras.custom_fields.filter(
                content_types="ipam.ipaddress"
            )
        }

        for label in NAUTOBOT_CUSTOM_FIELDS - fields_already_present:
            self.client.extras.custom_fields.create(
                label=label,
                type="text",
                description="DHCP Lease metadata for pydhcp",
                content_types=["ipam.ipaddress"],
            )
            logger.info(f"Created custom field {label} in Nautobot")
        logger.info(f"Nautobot backend {self.url} connected and ready.")


    def offer(self, packet):
        """ Generate an appropriate offer based on packet.  Return a dhcp.lease.Lease object """

        nbip, prefix, device, _ = self._find_lease(packet)
        if not nbip:
            return None

        lease = self._nbip_to_lease(nbip)
        self._add_network_settings_to_lease(lease, device, prefix)

        # Reserve the lease for 10 secs pending the clients REQUEST
        self._update_dynamic_ip(packet, nbip, 10)

        return lease


    def acknowledge_selecting(self, packet: Packet, offer: Lease) -> Lease:
        """ Check if the offer was dynamic, if so set the full expiry """

        if not offer:
            return

        ip_addresses = self.client.ipam.ip_addresses.filter(
            address=str(offer.client_ip),
            cf_pydhcp_mac=packet.client_mac.upper(),
            type=IPADDRESS_DHCP_TYPE,
        )
        if ip_addresses:
            device, interface = self._find_device_and_interface(packet.client_mac)
            self._update_dynamic_ip(packet, ip_addresses[0], self.lease_time, device, interface)

        return offer

    def acknowledge_renewing(self, packet, offer=None):
        """ Find the lease and extend """
        nbip, prefix, device, interface = self._find_lease(packet)
        if not nbip:
            return

        requested_ip = getattr(
            packet.find_option(PacketOption.REQUESTED_IP),
            "value", packet.ciaddr
        )
        if ipaddress.ip_interface(nbip.address).ip != requested_ip:
            logger.error("Resolved lease IP: %s, does not match requested IP: %s in renewal",
                         ipaddress.ip_interface(nbip.address).ip, requested_ip)
            return None

        lease = self._nbip_to_lease(nbip)
        self._add_network_settings_to_lease(lease, device, prefix)
        self._update_dynamic_ip(packet, nbip, self.lease_time, device, interface)

        return lease

    def acknowledge_rebinding(self, packet, offer=None):
        """ Find a lease, if it matches the requested return it else return none """
        return self.acknowledge_renewing(packet, offer)

    def acknowledge_init_reboot(self, packet, offer=None):
        """ Find a lease, if it matches the requested return it else return none """
        return self.acknowledge_renewing(packet, offer)

    def release(self, packet):
        """ Action release request as per packet.

        Bring the expiry time forward, but remember the MAC.
        """
        ip_addresses = self.client.ipam.ip_addresses.filter(
            address=packet.ciaddr,
            cf_pydhcp_mac=packet.client_mac.upper(),
            type=IPADDRESS_DHCP_TYPE,
        )

        expire = datetime.now(timezone.utc).isoformat()
        for ip_address in ip_addresses:
            logger.info(f"Expiring lease {ip_address} due to DHCP Release")
            ip_address.custom_fields["pydhcp_expire"] = expire
            ip_address.save()

    def boot_request(self, packet, lease):
        """ Add boot params to the supplied lease """

        device, _ = self._find_device_and_interface(packet.client_mac)

        if device is None:
            logger.warning(
                "Received boot request from unknown machine with MAC: %s",
                packet.client_mac.upper(),
            )
            return

        if not device.custom_fields.get("redeploy", False):
            return

        confirmation = device.custom_fields.get("confirm_redeploy", "")
        if confirmation != device.name:
            logger.warning("Redeploy set on device %s, but confirmation does not match: %s",
                           device.name, confirmation)
            return

        tftp_server = obj_or_dict_get(pydhcp_configuration, "tftp_server", None)
        boot_filepath = None

        if packet.client_arch in ("Intel x86PC",):
            boot_filepath = obj_or_dict_get(pydhcp_configuration, "pxe_boot_file", None)
        if packet.client_arch in ("EFI BC", "EFI x86-64"):
            boot_filepath = obj_or_dict_get(pydhcp_configuration, "uefi_boot_file", None)

        if tftp_server and boot_filepath:
            lease.tftp_server = tftp_server
            lease.tftp_filename = boot_filepath

    def _find_lease(self, packet):
        """ Find a lease for the discover/request using the following process

        Find an existing IP Address in Nautobot, either:

        assigned to an Interface with this client MAC address

        OR

        with custom field pydhcp_mac whose value is this MAC address

        OR

        Create an IP Address using available IP space in the subnet

        OR

        If no free IP, recycle the oldest DHCP IP with expired lease
        """

        prefix = self._find_origin_prefix(packet)
        if not prefix:
            return None, None, None, None

        device, interface = self._find_device_and_interface(packet.client_mac)

        nbip = None
        try:
            nbip = self._find_static_lease(interface, prefix) or \
                self._find_dynamic_lease(packet.client_mac, prefix)
        except DHCPIgnore:
            pass

        if nbip is None:
            return None, None, None, None

        return nbip, prefix, device, interface

    def _find_static_lease(self, interface, prefix):
        if interface is None:
            return None

        logger.debug(f"find static lease on {interface} in {prefix}")
        if interface and interface.lag:
            # Link aggregation interface member we need to only service ONE
            # member else, it will hand the the same IP to both memebers if they
            # come up independantly (e.g. PXE).  Assumes that the member
            # interfaces retain their individual MAC addresses while the LAG
            # takes on the MAC of one of its members.
            if interface.mac_address != interface.lag.mac_address:
                raise DHCPIgnore()

            interface = interface.lag

        ip = self.client.ipam.ip_addresses.get(
            parent=prefix.id,
            interface_id=interface.id,
        )
        return ip and ipaddress.ip_interface(ip.address)


    def _find_dynamic_lease(self, mac_address, prefix):
        ip_addresses = self.client.ipam.ip_addresses.filter(parent=prefix.id)
        # most recently active last
        ip_addresses.sort(
            key=lambda i: i.custom_fields.get("pydhcp_expire") or "1970-01-01"
        )

        # Most recent IP leased to this actual mac address, regadless of `type`
        for ip in reversed(ip_addresses):
            if ip.custom_fields.get("pydhcp_mac") == mac_address.upper():
                logger.debug(f"Lease {ip} {ip.id}, already assigned to {mac_address}")
                return ip

        # First free IP in the pool
        used = {ipaddress.IPv4Address(ip.host) for ip in ip_addresses}
        pool = list(ipaddress.IPv4Network(prefix.prefix))[DHCP_POOL_SLICE]
        free_ips = [ip for ip in pool if ip not in used]
        logger.debug(f"Finding dyncamic lease for {mac_address} in {prefix} "
                     f"pool size {len(pool)} used {len(used)} "
                     f"available {len(free_ips)}")

        if free_ips:
            ip = free_ips[0]
            logger.debug(f"Assigned {ip}, lowest available from {prefix}")
            return self.client.ipam.ip_addresses.create(
                parent=prefix.id,
                address=str(ip),
                status="Active",
                type=IPADDRESS_DHCP_TYPE,
                cf_pydhcp_expire=self.expiry_timestamp(self.lease_time),
                cf_pydhcp_mac=mac_address.upper(),
            )

        # oldest expired DHCP-type ip address
        # missing expiry date counts as expired
        now = datetime.now(timezone.utc)
        old_dhcp = [ip for ip in ip_addresses if ip.type == IPADDRESS_DHCP_TYPE]
        for ip in old_dhcp:
            expire = ip.custom_fields["pydhcp_expire"]
            if not expire:
                logger.debug(f"Assigned {ip}, DHCP with no expiry date set")
                return ip
            try:
                expire = datetime.fromisoformat(expiry)
                if now > expire:
                    logger.debug(f"Assigned {ip}, it expired {expire}")
                    return ip
            except Exception:
                pass

        logger.info(f"No leases available in {prefix} for {mac_address}")
        return None

    def _update_dynamic_ip(self, packet, ipaddr, expiry, device=None, interface=None):
        if not ipaddr:
            return

        if ipaddr.type != IPADDRESS_DHCP_TYPE:
            # Not a dynamic address
            return

        ipaddr.custom_fields["pydhcp_mac"] = packet.client_mac.upper()
        ipaddr.custom_fields["pydhcp_expire"] = self.expiry_timestamp(expiry)
        ipaddr.custom_fields["pydhcp_hostname"] = packet.client_hostname

        if interface:
            ipaddr.interface = interface
        ipaddr.save()

    def expiry_timestamp(self, seconds_hence):
        _time = datetime.now(timezone.utc) + timedelta(seconds=seconds_hence)
        return _time.isoformat()


    def _nbip_to_lease(self, ipaddr):
        ipaddr = ipaddress.ip_interface(ipaddr.address)

        return Lease(
            client_ip=ipaddr.ip,
            client_mask=ipaddr.network.netmask,
            lifetime=self.lease_time,
        )

    def _add_network_settings_to_lease(self, lease, device, prefix):
        # TODO: nautobot prefixes can have a gateway IP address

        # default to using the first IP address in the block as default gateway
        default_gateway_ip = ipaddress.IPv4Network(prefix.prefix)[GATEWAY_INDEX]
        lease.router = default_gateway_ip

        dns_server_ips = []
        if dns_server_ips:
            lease.dns_addresses = [
                ipaddress.ip_address(ip) for ip in dns_server_ips]

    def _find_device_and_interface(self, mac_address):
        # The api to lookup virtual interfaces by mac appears to be broken, but we can get the
        # device directly with mac and then enumerate its interfaces to get the correct one.

        device = self.client.dcim.devices.get(mac_address=mac_address.upper()) or \
            self.client.virtualization.virtual_machines.get(mac_address=mac_address.upper())

        if device is None:
            return None, None

        if hasattr(device, "vcpus"):
            # virtual machine
            interfaces = self.client.virtualization.interfaces.filter(virtual_machine_id=device.id)
        else:
            interfaces = self.client.dcim.interfaces.filter(device_id=device.id)

        interface = None
        for _i in interfaces:
            if _i.mac_address and _i.mac_address.upper() == mac_address.upper():
                interface = _i
                break

        return device, interface

    def _find_origin_prefix(self, packet):
        """Return the Nautobot Prefix relevant to this request.

        The client IP, relay IP or server's local IP are used to find the
        approriate subnet.

        We only consider prefixes that have one of our required Roles.

        If multiple prefixes are present we find the most-specific one.
        """

        requested_ip = getattr(
            packet.find_option(PacketOption.REQUESTED_IP),
            "value", packet.ciaddr
        )

        if requested_ip.is_unspecified is False:
            # Return the prefix for the requested IP
            prefixes = self.client.ipam.prefixes.filter(
                contains=str(requested_ip), role=PREFIX_DHCP_ROLE
            )
        else:
            ipaddr = str(packet.receiving_ip)
            prefixes = self.client.ipam.prefixes.filter(
                contains=str(ipaddr), role=PREFIX_DHCP_ROLE
            )

        if not prefixes:
            logger.warning(
                f"No Nautobot prefix found containing {packet.receiving_ip} "
                f"with role of {PREFIX_DHCP_ROLE}"
            )
            return None

        return max(prefixes, key=lambda p: p.prefix_length)

    @classmethod
    def add_backend_args(cls):
        """ Add argparse arguments for this backend """
        group = SETTINGS.add_argument_group(title=cls.NAME, description=cls.__doc__)
        group.add_argument("--nautobot-url", help="The Nautobot instance URL")
        group.add_argument("--nautobot-token", help="The nautobot authentication token")
        group.add_argument("--nautobot-allow-unknown-devices",
                           help="Allow dynamic leases for unknown devices",
                           action="store_true")
try:
    import pynautobot
    NautobotBackend.add_backend_args()
except ImportError as ex:
    NautobotBackend.DISABLED = str(ex)


def obj_or_dict_get(ctx, key, default=None):
    """Currently depending on the class of object holding the context, the context may be
    a dict or an object.
    """
    if isinstance(ctx, dict):
        return ctx.get(key, default)

    return getattr(ctx, key, default)


class DHCPIgnore(Exception):
    pass



