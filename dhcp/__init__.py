""" PyDHCP """

import os
import sys
import logging

from dhcp.server import Server
from dhcp.backends import get_backend
from dhcp.settings import SETTINGS

logger = logging.getLogger("dhcp")
logger.setLevel(logging.INFO)
logger.addHandler(
    logging.StreamHandler()
)


def run():
    """ Run dhcp """
    SETTINGS.parse()

    backend = get_backend(SETTINGS.backend)
    server = Server(backend=backend(),
                    interface=SETTINGS.interface,
                    listen_udp_port=SETTINGS.listen_udp_port,
                    authoritative=SETTINGS.authoritative,
                    server_ident=SETTINGS.server_ident)

    logger.info(f"Starting DHCP server on port {SETTINGS.listen_udp_port}")

    while True:
        try:
            server.serve()
        except KeyboardInterrupt:
            break
        except Exception as ex:
            logger.error("Error running DHCP server: %s", str(ex), exc_info=True)

    logger.info("DHCP server stopped")


if __name__ == "__main__":
    run()
