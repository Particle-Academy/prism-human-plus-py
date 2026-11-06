"""Explicit shared relay address policy, independent of native private flags."""

import ipaddress

_NON_PUBLIC = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/96",
        "::ffff:0:0/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)

# NAT64 and 6to4 carry an IPv4 address inside an IPv6 one, and the packet goes
# to the embedded address, so that is what is judged. Not refused outright: a
# DNS64 network gives public sites 64:ff9b:: addresses.
# (network, byte offset of the embedded IPv4)
_EMBEDDING = (
    (ipaddress.ip_network("::ffff:0:0/96"), 12),
    (ipaddress.ip_network("64:ff9b::/96"), 12),
    (ipaddress.ip_network("2002::/16"), 2),
)


def is_non_public_address(text: str) -> bool:
    if "%" in text:
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True
    if address.version == 6:
        for network, offset in _EMBEDDING:
            if address in network:
                return is_non_public_address(
                    str(ipaddress.IPv4Address(address.packed[offset : offset + 4]))
                )
    return any(address in network for network in _NON_PUBLIC)
