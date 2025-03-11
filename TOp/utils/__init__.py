"""
Utility functions and helper components for system operations,
data management, and cross-module functionality.
"""

# Export primary utility components
from .logging import setup_logger, setup_enhanced_logging
from .device_db import DeviceDatabase
from .helpers import (
    validate_mac_address, format_mac_address, generate_random_mac,
    extract_oui, is_broadcast_mac, is_multicast_mac,
    channel_to_frequency, frequency_to_channel,
    get_current_timestamp, get_formatted_time,
    get_interface_info, is_root, require_root,
    find_wireless_interfaces, enable_monitor_mode, disable_monitor_mode,
    hash_data, get_host_info, check_dependencies
)

# Constants
UTIL_VERSION = '0.1.0'
DEFAULT_LOG_LEVEL = 'INFO'

__all__ = [
    'setup_logger',
    'setup_enhanced_logging',
    'DeviceDatabase',
    'validate_mac_address',
    'format_mac_address',
    'generate_random_mac',
    'extract_oui',
    'is_broadcast_mac',
    'is_multicast_mac',
    'channel_to_frequency',
    'frequency_to_channel',
    'get_current_timestamp',
    'get_formatted_time',
    'get_interface_info',
    'is_root',
    'require_root',
    'find_wireless_interfaces',
    'enable_monitor_mode',
    'disable_monitor_mode',
    'hash_data',
    'get_host_info',
    'check_dependencies'
]

def initialize_utilities():
    """Initialize utility subsystems"""
    # Set up enhanced logging
    setup_enhanced_logging()
    
    # Check system capabilities
    capabilities = check_dependencies()
    
    # Check for root privileges - important for wireless operations
    root_available = is_root()
    
    return {
        'dependencies': capabilities,
        'root_available': root_available
    } 