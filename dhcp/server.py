"""A Python DHCP server with pluggable lease backends.

TODO:

- organise execution in threads communicating via queues:
    listen/receive -> process <-> query-backend

- better cacheing, make fewer calls to the backend

- "de-duplicate" the queue to avoid balooning the listen queue when we are
  unresponsive due to load and a slow backend.  When clients retry we can
  discard all but last request.

"""

import logging
import select
import ipaddress
import socket
from collections import OrderedDict
import netifaces

from dhcp.utils import format_mac
from dhcp.packet import Packet, PacketType, PacketOption, Option, MessageType

logger = logging.getLogger("dhcp")

CLIENT_STATE_SELECTING = "SELECTING"
CLIENT_STATE_REQUESTING = "REQUESTING"
CLIENT_STATE_BOUND = "BOUND"
CLIENT_STATE_RENEWING = "RENEWING"
CLIENT_STATE_REBINDING = "REBINDING"
CLIENT_STATE_INIT_REBOOT = "INITREBOOT"
CLIENT_STATE_UNKNOWN = "UNKNOWN"


def get_client_state(packet):
    """ Determine client state from DHCP REQUESTfrom DHCP REQUEST

    See RFC2131 4.3.2.
    """

    def _is_specified(ipaddr):
        """ Readability helper """
        return ipaddr.is_unspecified is False

    if packet.find_option(PacketOption.MESSAGE_TYPE).value == MessageType.DHCPDISCOVER:
        return CLIENT_STATE_SELECTING

    if packet.find_option(PacketOption.MESSAGE_TYPE).value == MessageType.DHCPREQUEST:
        if _is_specified(packet.srciaddr) and packet.giaddr.is_unspecified:
            # Unicast at the at the IP level by the client.
            # There is a src address without using a proxy
            if packet.find_option(PacketOption.SERVER_IDENT) is None and \
                    packet.find_option(PacketOption.REQUESTED_IP) is None and \
                    packet.ciaddr != ipaddress.ip_address("0.0.0.0"):
                return CLIENT_STATE_RENEWING

        else:
            # broadcast by the client at the IP level.
            # either the src address of the packet is 0.0.0.0 OR
            # the src address is attributable to a proxy
            if packet.find_option(PacketOption.SERVER_IDENT) and \
                    packet.find_option(PacketOption.REQUESTED_IP) and \
                    packet.ciaddr == ipaddress.ip_address("0.0.0.0"):
                return CLIENT_STATE_SELECTING

            if packet.find_option(PacketOption.SERVER_IDENT) is None and \
                    packet.find_option(PacketOption.REQUESTED_IP) is None and \
                    packet.ciaddr != ipaddress.ip_address("0.0.0.0"):
                return CLIENT_STATE_REBINDING

            if packet.find_option(PacketOption.SERVER_IDENT) is None and \
                    packet.find_option(PacketOption.REQUESTED_IP) is not None and \
                    packet.ciaddr == ipaddress.ip_address("0.0.0.0"):
                return CLIENT_STATE_INIT_REBOOT

    return CLIENT_STATE_UNKNOWN


class Server():
    """ A DHCP server """

    _MAX_XID_STORED = 1000
    _REQUESTS = OrderedDict()
    _IPADDRS = {}

    def __init__(self, backend, interface="*",
                 listen_udp_port=67, server_name=None,
                 authoritative=False, server_ident=None):
        self.backend = backend
        self.server_name = server_name or socket.gethostname()
        self.authoritative = authoritative
        self.server_ident = None

        if server_ident:
            try:
                self.server_ident = ipaddress.ip_address(server_ident)
            except ValueError:
                logger.error("supplied server_ident %s is not a valid IP address", server_ident)

        self.handlers = {
            MessageType.DHCPDISCOVER: self.handle_discover,
            MessageType.DHCPREQUEST: self.handle_request,
            MessageType.DHCPRELEASE: self.handle_release,
        }

        self.request_state_handlers = {
            CLIENT_STATE_SELECTING: backend.acknowledge_selecting,
            CLIENT_STATE_RENEWING: backend.acknowledge_renewing,
            CLIENT_STATE_REBINDING: backend.acknowledge_rebinding,
            CLIENT_STATE_INIT_REBOOT: backend.acknowledge_init_reboot,
        }

        self._IPADDRS = self.setup_sockets(interface, listen_udp_port)

    def serve(self):
        """ Start the server and process incomming requests """

        while True:
            rlist, _, _ = select.select(list(self._IPADDRS.keys()), [], [])
            if rlist:
                for sock in rlist:
                    data, address = sock.recvfrom(1024)
                    src_addr, src_port = address

                    if src_port not in [67, 68]:
                        logger.debug(f"Accepted packet from unexpected UDP port {src_port}")
                        #continue

                    packet = Packet()
                    packet.inaddr = self.server_ident or self._IPADDRS[sock]
                    packet.srciaddr = ipaddress.ip_address(src_addr)
                    packet.unpack(data)

                    message_type = packet.find_option(
                        PacketOption.MESSAGE_TYPE
                    )
                    if not message_type:
                        logger.debug(
                            "Malformed packet: no MESSAGE_TYPE option"
                        )
                        continue

                    handler = self.handlers.get(message_type.value)
                    if handler:
                        handler(sock, packet)

    def handle_discover(self, sock, packet):
        """ Handle a DHCP Discover message """

        logger.info("%s: Received DISCOVER", format_mac(packet.chaddr))

        try:
            lease = self.backend.offer(packet)
        except Exception as ex:
            logger.error("Backend produced an error handling discover: %s", str(ex), exc_info=ex)
            return

        if not lease:
            return

        if 66 in packet.requested_options and 67 in packet.requested_options:
            logger.debug(
                f"Boot parameters requested, client arch {packet.client_arch}"
            )
            self.backend.boot_request(packet, lease)

        self._store_lease(packet.xid, lease)
        offer = packet.response_from_lease(lease)

        logger.info("%s: Sending OFFER %s", format_mac(packet.chaddr), str(lease))
        self.send_packet(sock, offer)

    def handle_request(self, sock, packet):
        """ Handle a DHCP Request message """

        client_state = get_client_state(packet)
        requested_ip = getattr(packet.find_option(PacketOption.REQUESTED_IP), "value", None) \
            or packet.ciaddr
        logger.info(
            "%s: Received REQUEST(%s) for %s", format_mac(packet.chaddr), client_state, requested_ip
        )

        lease = None
        handler = self.request_state_handlers.get(client_state, None)

        if handler is None:
            logger.error("Received unhandlable REQUEST state: %s", client_state)
            packet.dump()
            return

        if client_state == CLIENT_STATE_SELECTING:
            server_ident_opt = packet.find_option(PacketOption.SERVER_IDENT)
            valid_idents = list(self._IPADDRS.values()) + [self.server_ident]
            if server_ident_opt.value not in valid_idents:
                logger.error(
                    f"REFUSING request which specified {server_ident_opt=}, "
                    f"expected {valid_idents=}"
                )
                return

            lease = self._load_lease(packet.xid)
            if not lease:
                logger.warning("No offer cached for request identifying this server")
            elif requested_ip != lease.client_ip:
                raise Exception(
                    f"Request is for {requested_ip} but lease is {lease.client_ip}"
                )

        try:
            lease = handler(packet, lease)
        except Exception as ex:
            logger.error("Backend produced an error handling request: %s", str(ex), exc_info=ex)
            lease = None

        if lease is None:
            if self.authoritative:
                nack = Packet()
                nack.clone_from(packet)
                nack.op = PacketType.BOOTREPLY
                nack.htype = packet.htype
                nack.yiaddr = 0
                nack.siaddr = 0
                nack.options.append(Option(PacketOption.MESSAGE_TYPE,
                                           MessageType.DHCPNAK))

                logger.info("%s: Sending NACK", format_mac(packet.chaddr))
                self.send_packet(sock, nack)
            else:
                logger.info("%s: Suppressing NACK because not authoritative", format_mac(packet.chaddr))
            return

        ack = packet.response_from_lease(lease)
        logger.info("%s: ACKNOWLEDGING %s", format_mac(packet.chaddr), str(lease))

        self.send_packet(sock, ack)

    def handle_release(self, sock, packet):
        """ Handle a DHCP release message """
        logger.info("%s: Received Release", format_mac(packet.chaddr))
        self.backend.release(packet)

    def setup_sockets(self, specified_interface, udp_port):
        """ Setup a socket for each interface to serve on """

        if specified_interface in ("", "*"):
            interface_names = self.all_interfaces_with_ip()
        else:
            interface_names = [specified_interface]

        return dict(self._make_sock(i, udp_port) for i in interface_names)

    def all_interfaces_with_ip(self):
        interface_names = {
            iface for iface in netifaces.interfaces()
                if netifaces.AF_INET in netifaces.ifaddresses(iface)
        }
        if not interface_names:
            raise Exception("No interfaces found")
        return interface_names

    def _make_sock(self, iface, udp_port):
        try:
            addrs = netifaces.ifaddresses(iface)
        except ValueError:
            raise Exception(f"Invalid interface {iface}") from None

        if netifaces.AF_INET not in addrs:
            raise Exception(f"Interface {iface} has no IP address set")

        ipaddr = ipaddress.IPv4Address(addrs[netifaces.AF_INET][0]["addr"])
        name_z = str(iface + "\0").encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, name_z)

        sock.bind(("0.0.0.0", udp_port))
        return sock, ipaddr

    @staticmethod
    def send_packet(sock, packet):
        """ Send packet to client """

        dst = "255.255.255.255"
        dport = 68

        if not packet.ciaddr.is_unspecified:
            dst = str(packet.ciaddr)

        if not packet.giaddr.is_unspecified:
            dst = str(packet.giaddr)
            dport = 67

        sock.sendto(packet.pack(), (dst, dport))

    def _store_lease(self, xid, lease):
        self._REQUESTS[xid] = lease

        while len(self._REQUESTS) > self._MAX_XID_STORED:
            self._REQUESTS.popitem(last=False)

    def _load_lease(self, xid):
        return self._REQUESTS.get(xid, None)
