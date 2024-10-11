# PyDHCP

## Introduction

The PyDHCP package provides a DHCP server written in Python that is relatively
easy to extend with custom backends for managing lease and IP allocation
information.

This fork rewrites some of the original to add Rackspace-centric functionality
and integrate with Nautobot as a backend.

It provides functionality specifically taylored to assign IP addresses to DRACs,
with the assumption that:

- we are deployed with a UDP ingress that is reachable on port 67/udp from DRAC
- DRAC is on a VLAN configured with a DHCP helper address pointed at pydhcp's IP
- pydhcp is configured with credentials to reach a nautobot instance
- the nautobot instance has an ipam Prefix for the DRAC VLAN
- nautobot has full responsibility for assigning IP addresses in the DRAC VLAN
- anyone taking an IP address in the DRAC VLAN will create an IP Addresses in nautobot
- the first 5 addresses in each subnet are reserved for gateway/routers, etc

## Installation

Poetry is used.

Please see Dockerfile provided.

## Usage

The basic usage provides for 3 command line arguments:
 * `-i|--interface`: specify `*` to listen on all interfaces, or specify one or more times with an interface name (e.g. "eth0") to listen on specific interfaces.
 * `-a|--authoritive`: boolean flag. Authoritative DHCP servers send a NAK to clients it does not wish to provide a lease to which will effectively stop DHCP on the client.  Non-authoritative servers will simply ignore the client leaving other DHCP servers free to respond.
 * `-b|--backend`: the name of the backend to use.  The selection of a backend will invoke the need for backend specific arguments.

E.g:
```
> dhcp -i * -a --backend=netbox <netbox arguments>
```

## Backends

### Nautobot

The nautobot backend is similar to the original netbox backend, differences are:

- IP allocation strategy: the Netbox backend required IP addresses to be created
  in the database for every ip address in the DHCP scope, as well as the
  "default gateway" for the subnet.

  To make it easier to manage at scale, I made these items implicit, so that all
  that needs to be present in Nautobot is a Prefix for our DHCP subnet.
    
  We assume the following IP assignment conventions: the first 5 addresses in
  the subnet are reserved and will never be handed out to DHCP clients.  The
  last IP address in the subnet is obviously reserved for broadcast address.
  
  DHCP clients are given the first address in the subnet as their default gateway.

- Nautobot IP addresses with "DHCP" type are considered to "belong" to the DHCP
  server and can be created, expired, re-assigned, etc., in response to requests
  on that subnet.

  If other types of IP address are present and associated with a client MAC
  address, we will lease those IP addresses, but the DHCP server will not alter
  those records in nautobot - they can be considered "permanent" leases.

- Unlike the netbox backend, we don't ever create an association from IP address
  to interface or from ip address to device (i.e. to set its primary IP)
  
- PXE has not been tested with this backend and it is likely that the "custom
  config" parts will require some work before they are useable on nautobot.
  
- "Custom fields" that we neeed in Nautobot are automatically created on startup
  if they don't already exist.

### Netbox (original pydhcp backend)

The netbox backend will use a netbox instance to generate lease information.  Static leases are achieved by configuring a Device or Virtual Machine with a network interface that has the MAC address properly set and an IP address assigned.  If this is the case, PyDHCP will identify the interface by matching the MAC address with that of the incoming DISCOVER/REQUEST and provide the configured IP.

Dynamic leases are achievable by setting the status of IP addresses as `DHCP`.

#### Basic Setup Requirements

 * There must be a prefix defined containing any IP address you want PyDHCP to allocate.
 * The default gateway for any lease is determined by the IP address within the allocation's prefix that is tagged `Gateway`.
 * DNS servers for any lease is determined by looking up `config_context['pydhcp_configuration']['dns_servers']`.  The value must be a list of IP addresses.  When generating a lease for a MAC address that resolves to an Interface attached to a Device or Virtual Machine, the Configuration Context of the Device or Virtual Machine will be used.  In other cases, the configuration context for the site to which the Prefix is allocated will be used.

There are a number of values that are looked up via the configuration context data that netbox provides.  Configuration context is a hierachical process of applying configuration type data to objects whereby configuration data is overlayed in order of priority/scope to reach the final configuration as it applies to a specific object.  How to specifically structure the config data in your environment will depend on you circumstances, as long as the devices (and sites in some cases) have the required context rendered for them.  For more information on configuration contexts, see https://netbox.readthedocs.io/en/stable/additional-features/context-data/

#### Supporting Dynamic Leases
If you wish to support dynamic leases, the following custom fields will need to be setup in netbox and applied to `IPAM->IP Address` objects:
 * `pydhcp_mac`: text field used to store the MAC address to which the IP was last allocated. Set required=false, no default.
 * `pydhcp_expire`: used to store the expiry time of the lease. Set required=false, no default.
 * `pydhcp_hostname`: used to store the hostname in the DHCP discover/request.  Handy when providing IPs to unknown devices, or devices
 without interfaces to which the IP can be attached.

Note that these names for the custom fields are the internal names.  You may use whatever labels/descriptions for the fields suit your fancy.

To make an IP address available for dynamic assignment, create the prefix, and IP addresses and set the status of the IP address to `DHCP`.

#### Supporting Automated Deployment (PXE Booting)

The netbox backend provides a process for supporting the automated deployment of Devices and Virtual Machines during the PXE boot phase of a device's boot sequence.  To this end, if the DISCOVER/REQUEST packet's include requests for boot related options, PyDHCP can populate the lease options with the IP of a TFTP service and the file to request from the TFTP server.  These additional fields are required to be available in the `pydhcp_configuration` section of a Device's configuration context:
 * `tftp_server`: the IP address of the TFTP server
 * `pxe_boot_file`: the path of the file to load via TFTP in the case of legacy, non UEFI based, bioses.  Required if supporting such systems.
 * `uefi_boot_file`: the path of the file to load via TFTP in the case of UEFI based boot processes.  Required if supporting such systems.

An example `pydhcp_configuration` config context looks like:

```json
{
    "pydhcp_configuration": {
        "dns_servers": [
            "192.168.10.3"
        ],
        "pxe_boot_file": "centos7/pxelinux.0",
        "tftp_server": "192.168.10.5"
    }
}
```
