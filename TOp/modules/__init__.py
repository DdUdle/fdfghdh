"""
Module components for hardware interaction, packet manipulation, 
and device tracking capabilities.
"""

import importlib.util
import sys
import os

# Test for scapy availability
PACKET_CRAFTING_AVAILABLE = importlib.util.find_spec("scapy") is not None

# Test for monitor mode capability
MONITOR_MODE_AVAILABLE = False
try:
    from ..utils.helpers import find_wireless_interfaces
    interfaces = find_wireless_interfaces()
    MONITOR_MODE_AVAILABLE = len(interfaces) > 0
except:
    pass

# Export primary module components
from .packet_crafter import PacketCrafter
from .fingerprinting import Fingerprinter as DeviceFingerprinter
from .channel_hopping import ChannelHopper
from .client_trayker import ClientTracker

__all__ = [
    'PacketCrafter',
    'DeviceFingerprinter',
    'ChannelHopper',
    'ClientTracker',
    'PACKET_CRAFTING_AVAILABLE',
    'MONITOR_MODE_AVAILABLE'
]

def get_available_interfaces():
    """Get list of available wireless interfaces"""
    from ..utils.helpers import find_wireless_interfaces
    return find_wireless_interfaces()

def check_interface_capabilities(interface_name):
    """Check capabilities of specific interface"""
    from ..utils.helpers import get_interface_info
    return get_interface_info(interface_name) 