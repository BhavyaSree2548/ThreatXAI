"""Network interface discovery module supporting Windows, Linux, and Cloud environments."""

from __future__ import annotations

import socket
import sys
from .models import InterfaceInfo


def get_available_interfaces() -> list[InterfaceInfo]:
    """Discover real network interfaces available on the system."""
    discovered: list[InterfaceInfo] = []
    seen_names: set[str] = set()

    # 1. Try Windows Scapy interface discovery
    if sys.platform.startswith("win"):
        try:
            from scapy.arch.windows import get_windows_if_list
            scapy_ifaces = get_windows_if_list()
            for item in scapy_ifaces:
                name = item.get("name") or item.get("description") or item.get("guid") or "Unknown"
                desc = item.get("description") or name
                ips = [str(ip) for ip in item.get("ips", []) if ip]
                
                # Identify if interface is active/up
                has_ipv4 = any("." in ip and not ip.startswith("169.254") for ip in ips)
                is_up = bool(has_ipv4)

                if name in seen_names:
                    continue
                seen_names.add(name)

                discovered.append(
                    InterfaceInfo(
                        id=name,
                        name=name,
                        description=desc,
                        ips=ips,
                        is_up=is_up,
                    )
                )
        except Exception:
            pass

    # 2. Try Linux/Unix Scapy interface discovery
    if not discovered:
        try:
            from scapy.all import get_if_list
            if_list = get_if_list()
            for if_name in if_list:
                if if_name in seen_names:
                    continue
                seen_names.add(if_name)
                is_loopback = if_name in ("lo", "lo0")
                discovered.append(
                    InterfaceInfo(
                        id=if_name,
                        name=if_name,
                        description=f"Linux Interface ({if_name})",
                        ips=[],
                        is_up=not is_loopback,
                    )
                )
        except Exception:
            pass

    # 3. Fallback using standard socket hostname
    if not discovered:
        hostname = socket.gethostname()
        try:
            host_ip = socket.gethostbyname(hostname)
            discovered.append(
                InterfaceInfo(
                    id="Default",
                    name="Default Interface",
                    description=f"Host Adapter ({hostname})",
                    ips=[host_ip],
                    is_up=True,
                )
            )
        except Exception:
            discovered.append(
                InterfaceInfo(
                    id="Default",
                    name="Default Interface",
                    description="Standard Network Host Interface",
                    ips=["127.0.0.1"],
                    is_up=True,
                )
            )

    # Sort so active/up interfaces appear first
    discovered.sort(key=lambda x: (not x.is_up, x.name))
    return discovered
