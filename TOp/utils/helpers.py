"""
Wireless Network Analysis Framework - Utility Helpers

This module provides utility functions and helper classes for common operations
across the framework, including data processing, conversions, and system interactions.
"""

import os
import re
import sys
import time
import random
import logging
import hashlib
import socket
import subprocess
import ipaddress
from typing import Dict, List, Tuple, Optional, Union, Any
import json

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

def validate_mac_address(mac: str) -> bool:
    """
    Validate MAC address format
    
    Args:
        mac: MAC address string
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not mac:
        return False
    
    # Allow various formats
    # XX:XX:XX:XX:XX:XX
    # XX-XX-XX-XX-XX-XX
    # XXXXXXXXXXXX
    # XX.XX.XX.XX.XX.XX
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
        r'^([0-9A-Fa-f]{2}\.){5}([0-9A-Fa-f]{2})$',
        r'^[0-9A-Fa-f]{12}$'
    ]
    
    for pattern in patterns:
        if re.match(pattern, mac):
            return True
    
    return False

def format_mac_address(mac: str, separator: str = ':') -> str:
    """
    Format MAC address to consistent format
    
    Args:
        mac: MAC address string
        separator: Separator character (default: ':')
        
    Returns:
        str: Formatted MAC address
    """
    if not mac:
        return ""
    
    # Normalize to uppercase with no separators
    mac_normalized = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    
    # Check length
    if len(mac_normalized) != 12:
        return mac  # Return original if invalid
    
    # Format with separator
    return separator.join([mac_normalized[i:i+2] for i in range(0, 12, 2)])

def generate_random_mac(oui: str = None) -> str:
    """
    Generate a random MAC address
    
    Args:
        oui: OUI prefix (optional)
        
    Returns:
        str: Generated MAC address
    """
    if oui:
        # Format OUI
        oui = oui.replace(':', '').replace('-', '')
        
        # Ensure OUI is 6 hex digits
        if len(oui) != 6 or not all(c in '0123456789ABCDEFabcdef' for c in oui):
            raise ValueError("OUI must be 6 hex digits")
        
        # Generate random suffix
        suffix = ''.join(random.choice('0123456789ABCDEF') for _ in range(6))
        mac = oui + suffix
    else:
        # Use random OUI from locally administered range (avoid conflicts with real devices)
        first_byte = random.choice(['02', '06', '0A', '0E'])  # Set locally administered bit
        mac = first_byte + ''.join(random.choice('0123456789ABCDEF') for _ in range(10))
    
    # Format as XX:XX:XX:XX:XX:XX
    return ':'.join([mac[i:i+2] for i in range(0, 12, 2)])

def extract_oui(mac: str) -> str:
    """
    Extract OUI (first 3 bytes) from MAC address
    
    Args:
        mac: MAC address string
        
    Returns:
        str: OUI part of the MAC address
    """
    if not mac:
        return ""
    
    # Normalize
    mac_normalized = mac.upper().replace(':', '').replace('-', '').replace('.', '')
    
    # Extract first 6 characters (3 bytes)
    if len(mac_normalized) >= 6:
        return mac_normalized[:6]
    
    return ""

def is_broadcast_mac(mac: str) -> bool:
    """
    Check if MAC address is broadcast
    
    Args:
        mac: MAC address string
        
    Returns:
        bool: True if broadcast, False otherwise
    """
    return mac.lower() == 'ff:ff:ff:ff:ff:ff'

def is_multicast_mac(mac: str) -> bool:
    """
    Check if MAC address is multicast
    
    Args:
        mac: MAC address string
        
    Returns:
        bool: True if multicast, False otherwise
    """
    if not validate_mac_address(mac):
        return False
    
    # Get first byte
    first_byte = mac.replace(':', '').replace('-', '').replace('.', '')[:2]
    
    # Convert to integer
    try:
        value = int(first_byte, 16)
        # Check least significant bit of first byte
        return bool(value & 0x01)
    except ValueError:
        return False

def channel_to_frequency(channel: int, band: str = '2.4GHz') -> int:
    """
    Convert channel number to frequency
    
    Args:
        channel: Channel number
        band: Frequency band ('2.4GHz' or '5GHz')
        
    Returns:
        int: Frequency in MHz
    """
    if band == '2.4GHz':
        if 1 <= channel <= 14:
            if channel == 14:
                return 2484
            else:
                return 2407 + (channel * 5)
    elif band == '5GHz':
        if 36 <= channel <= 165:
            return 5000 + (channel * 5)
    
    raise ValueError(f"Invalid channel {channel} for band {band}")

def frequency_to_channel(frequency: int) -> Tuple[int, str]:
    """
    Convert frequency to channel number and band
    
    Args:
        frequency: Frequency in MHz
        
    Returns:
        tuple: (channel, band)
    """
    if 2412 <= frequency <= 2484:
        # 2.4 GHz band
        if frequency == 2484:
            return 14, '2.4GHz'
        else:
            return (frequency - 2407) // 5, '2.4GHz'
    elif 5170 <= frequency <= 5825:
        # 5 GHz band
        return (frequency - 5000) // 5, '5GHz'
    
    raise ValueError(f"Invalid frequency {frequency}")

def get_current_timestamp() -> float:
    """
    Get current timestamp in seconds
    
    Returns:
        float: Current timestamp
    """
    return time.time()

def get_formatted_time(timestamp: float = None, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format timestamp as string
    
    Args:
        timestamp: Timestamp in seconds (default: current time)
        format_str: Format string
        
    Returns:
        str: Formatted time string
    """
    if timestamp is None:
        timestamp = time.time()
    
    return time.strftime(format_str, time.localtime(timestamp))

def get_interface_info(interface: str) -> Dict:
    """
    Get information about a network interface
    
    Args:
        interface: Interface name
        
    Returns:
        dict: Interface information
    """
    info = {
        'name': interface,
        'exists': False,
        'mac_address': None,
        'is_wireless': False,
        'is_up': False,
        'ip_address': None
    }
    
    try:
        # Check if interface exists
        import fcntl
        import struct
        import array
        
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Get interface list
        max_possible = 128  # arbitrary. Would be unlimited on Linux
        bytes_buffer = max_possible * 32
        interface_names = array.array('B', b'\0' * bytes_buffer)
        interface_name_length = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes_buffer, interface_names.buffer_info()[0])
        ))[0]
        
        # Extract interface names
        interface_list = []
        for i in range(0, interface_name_length, 40):
            interface_list.append(interface_names[i:i+16].tobytes().split(b'\0')[0].decode())
        
        if interface not in interface_list:
            return info
        
        info['exists'] = True
        
        # Get interface flags
        ifreq = struct.pack('16s16x', interface.encode())
        flags = struct.unpack('H', fcntl.ioctl(
            s.fileno(),
            0x8913,  # SIOCGIFFLAGS
            ifreq
        )[16:18])[0]
        
        info['is_up'] = bool(flags & 0x1)  # IFF_UP
        
        # Get MAC address
        try:
            mac = fcntl.ioctl(
                s.fileno(),
                0x8927,  # SIOCGIFHWADDR
                struct.pack('256s', interface.encode())
            )[18:24]
            info['mac_address'] = ':'.join(['%02x' % b for b in mac])
        except Exception:
            pass
        
        # Get IP address
        try:
            ip = fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface.encode())
            )[20:24]
            info['ip_address'] = socket.inet_ntoa(ip)
        except Exception:
            pass
        
        # Check if wireless (presence of wireless extension)
        try:
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            info['is_wireless'] = 'no wireless extensions' not in result.stdout
        except Exception:
            pass
        
    except Exception as e:
        logger.error(f"Error getting interface info: {e}")
    
    return info

def is_root() -> bool:
    """
    Check if running as root
    
    Returns:
        bool: True if root, False otherwise
    """
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def require_root() -> bool:
    """
    Check if running as root and exit if not
    
    Returns:
        bool: True if root
    """
    if not is_root():
        logger.error("This program must be run as root")
        sys.exit(1)
    return True

def find_wireless_interfaces() -> List[str]:
    """
    Find wireless interfaces on the system
    
    Returns:
        list: List of wireless interface names
    """
    interfaces = []
    
    try:
        # Try using iwconfig
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        
        # Parse output
        for line in result.stdout.splitlines():
            if 'no wireless extensions' not in line and line.strip():
                interface = line.split()[0]
                interfaces.append(interface)
    except Exception:
        # Fallback to checking /sys/class/net
        try:
            for interface in os.listdir('/sys/class/net'):
                if os.path.exists(f'/sys/class/net/{interface}/wireless'):
                    interfaces.append(interface)
        except Exception as e:
            logger.error(f"Error finding wireless interfaces: {e}")
    
    return interfaces

def enable_monitor_mode(interface: str) -> Optional[str]:
    """
    Enable monitor mode on interface
    
    Args:
        interface: Interface name
        
    Returns:
        str: Monitor interface name or None if failed
    """
    try:
        # Check if already in monitor mode
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if 'Mode:Monitor' in result.stdout:
            return interface
        
        # Try using airmon-ng
        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], check=True)
            
            # Start monitor mode
            result = subprocess.run(['airmon-ng', 'start', interface], 
                               capture_output=True, text=True, check=True)
            
            # Extract monitor interface name
            for line in result.stdout.splitlines():
                if 'monitor mode' in line and 'enabled' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'on':
                            return parts[i+1].strip(')')
                    
                    # Fallback to interface name + 'mon'
                    return f"{interface}mon"
            
            # Fallback to original interface
            return interface
            
        except Exception:
            # Fallback to iw command
            try:
                # Set interface down
                subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
                
                # Set monitor mode
                subprocess.run(['iw', interface, 'set', 'monitor', 'none'], check=True)
                
                # Set interface up
                subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
                
                return interface
                
            except Exception as e:
                logger.error(f"Error enabling monitor mode with iw: {e}")
                return None
    
    except Exception as e:
        logger.error(f"Error enabling monitor mode: {e}")
        return None

def disable_monitor_mode(interface: str) -> Optional[str]:
    """
    Disable monitor mode on interface
    
    Args:
        interface: Interface name
        
    Returns:
        str: Managed interface name or None if failed
    """
    try:
        # Check if in monitor mode
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if 'Mode:Monitor' not in result.stdout:
            return interface
        
        # Try using airmon-ng
        try:
            # Stop monitor mode
            result = subprocess.run(['airmon-ng', 'stop', interface], 
                               capture_output=True, text=True, check=True)
            
            # Extract managed interface name
            for line in result.stdout.splitlines():
                if 'monitor mode' in line and 'disabled' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'on':
                            return parts[i+1].strip(')')
                    
                    # Try to get original interface name
                    if interface.endswith('mon'):
                        return interface[:-3]
                    return interface
            
            # Fallback to original interface
            return interface
            
        except Exception:
            # Fallback to iw command
            try:
                # Set interface down
                subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
                
                # Set managed mode
                subprocess.run(['iw', interface, 'set', 'type', 'managed'], check=True)
                
                # Set interface up
                subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
                
                return interface
                
            except Exception as e:
                logger.error(f"Error disabling monitor mode with iw: {e}")
                return None
    
    except Exception as e:
        logger.error(f"Error disabling monitor mode: {e}")
        return None

def hash_data(data: Union[str, bytes]) -> str:
    """
    Create SHA-256 hash of data
    
    Args:
        data: Data to hash
        
    Returns:
        str: Hexadecimal hash string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return hashlib.sha256(data).hexdigest()

def get_host_info() -> Dict:
    """
    Get information about the host system
    
    Returns:
        dict: Host information
    """
    info = {
        'os': os.name,
        'platform': sys.platform,
        'hostname': socket.gethostname(),
        'interfaces': [],
        'wireless_interfaces': []
    }
    
    # Get all interfaces
    try:
        import netifaces
        info['interfaces'] = netifaces.interfaces()
    except ImportError:
        # Fallback to listing /sys/class/net
        try:
            info['interfaces'] = os.listdir('/sys/class/net')
        except Exception:
            pass
    
    # Get wireless interfaces
    info['wireless_interfaces'] = find_wireless_interfaces()
    
    return info

def check_dependencies() -> Dict:
    """
    Check if required dependencies are installed
    
    Returns:
        dict: Dependency status
    """
    dependencies = {
        'aircrack-ng': {
            'required': True,
            'installed': False,
            'version': None
        },
        'iw': {
            'required': True,
            'installed': False,
            'version': None
        },
        'tcpdump': {
            'required': False,
            'installed': False,
            'version': None
        },
        'wireshark': {
            'required': False,
            'installed': False,
            'version': None
        },
        'python_packages': {
            'scapy': False,
            'numpy': False,
            'torch': False
        }
    }
    
    # Check command-line tools
    for cmd in ['aircrack-ng', 'iw', 'tcpdump', 'wireshark']:
        try:
            # Check if command exists
            result = subprocess.run(['which', cmd], capture_output=True, text=True)
            dependencies[cmd]['installed'] = result.returncode == 0
            
            if dependencies[cmd]['installed']:
                # Get version
                version_cmd = [cmd, '--version']
                result = subprocess.run(version_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    dependencies[cmd]['version'] = result.stdout.strip()
        except Exception:
            pass
    
    # Check Python packages
    try:
        import scapy
        dependencies['python_packages']['scapy'] = True
    except ImportError:
        pass
    
    try:
        import numpy
        dependencies['python_packages']['numpy'] = True
    except ImportError:
        pass
    
    try:
        import torch
        dependencies['python_packages']['torch'] = True
    except ImportError:
        pass
    
    return dependencies

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip: IP address string
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def parse_json_file(file_path: str) -> Optional[Dict]:
    """
    Parse JSON file
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        dict: Parsed JSON data or None if failed
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error parsing JSON file {file_path}: {e}")
        return None

def write_json_file(file_path: str, data: Any) -> bool:
    """
    Write data to JSON file
    
    Args:
        file_path: Path to JSON file
        data: Data to write
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error writing JSON file {file_path}: {e}")
        return False

def read_binary_file(file_path: str) -> Optional[bytes]:
    """
    Read binary file
    
    Args:
        file_path: Path to file
        
    Returns:
        bytes: File contents or None if failed
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading binary file {file_path}: {e}")
        return None

def write_binary_file(file_path: str, data: bytes) -> bool:
    """
    Write binary data to file
    
    Args:
        file_path: Path to file
        data: Data to write
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(file_path, 'wb') as f:
            f.write(data)
        return True
    except Exception as e:
        logger.error(f"Error writing binary file {file_path}: {e}")
        return False

def create_directory(path: str) -> bool:
    """
    Create directory if it doesn't exist
    
    Args:
        path: Directory path
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Error creating directory {path}: {e}")
        return False

def list_directory(path: str, pattern: str = None) -> List[str]:
    """
    List files in directory
    
    Args:
        path: Directory path
        pattern: File pattern (regex)
        
    Returns:
        list: List of file paths
    """
    try:
        files = os.listdir(path)
        
        if pattern:
            # Filter by pattern
            regex = re.compile(pattern)
            files = [f for f in files if regex.match(f)]
        
        # Get full paths
        return [os.path.join(path, f) for f in files]
    except Exception as e:
        logger.error(f"Error listing directory {path}: {e}")
        return []

def get_file_info(file_path: str) -> Dict:
    """
    Get information about a file
    
    Args:
        file_path: Path to file
        
    Returns:
        dict: File information
    """
    info = {
        'exists': False,
        'size': 0,
        'created_time': 0,
        'modified_time': 0,
        'is_directory': False,
        'is_file': False,
        'is_symlink': False,
        'permissions': 0
    }
    
    try:
        if not os.path.exists(file_path):
            return info
        
        info['exists'] = True
        info['is_directory'] = os.path.isdir(file_path)
        info['is_file'] = os.path.isfile(file_path)
        info['is_symlink'] = os.path.islink(file_path)
        
        # Get file stats
        stat_info = os.stat(file_path)
        info['size'] = stat_info.st_size
        info['created_time'] = stat_info.st_ctime
        info['modified_time'] = stat_info.st_mtime
        info['permissions'] = stat_info.st_mode & 0o777
        
    except Exception as e:
        logger.error(f"Error getting file info {file_path}: {e}")
    
    return info

def set_file_permissions(file_path: str, mode: int = 0o644) -> bool:
    """
    Set file permissions
    
    Args:
        file_path: Path to file
        mode: Permission mode
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        os.chmod(file_path, mode)
        return True
    except Exception as e:
        logger.error(f"Error setting file permissions {file_path}: {e}")
        return False

def execute_command(command: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """
    Execute shell command
    
    Args:
        command: Command as list of arguments
        timeout: Command timeout in seconds
        
    Returns:
        tuple: (exit_code, stdout, stderr)
    """
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", f"Error executing command: {e}"

def safe_execute(function: Callable, *args, **kwargs) -> Tuple[bool, Any]:
    """
    Execute a function safely, catching exceptions
    
    Args:
        function: Function to execute
        args: Positional arguments
        kwargs: Keyword arguments
        
    Returns:
        tuple: (success, result)
    """
    try:
        result = function(*args, **kwargs)
        return True, result
    except Exception as e:
        logger.error(f"Error executing function {function.__name__}: {e}")
        return False, None

class TemporaryPrivilegeEscalation:
    """Context manager for temporary privilege escalation"""
    
    def __init__(self, required_uid: int = 0):
        """
        Initialize the context manager
        
        Args:
            required_uid: Required user ID (default: 0 for root)
        """
        self.required_uid = required_uid
        self.original_euid = None
    
    def __enter__(self):
        """Enter the context - escalate privileges"""
        if hasattr(os, 'geteuid') and hasattr(os, 'seteuid'):
            self.original_euid = os.geteuid()
            
            if self.original_euid != self.required_uid:
                try:
                    os.seteuid(self.required_uid)
                    logger.debug(f"Temporarily escalated privileges to UID {self.required_uid}")
                except Exception as e:
                    logger.error(f"Failed to escalate privileges: {e}")
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context - restore privileges"""
        if self.original_euid is not None and hasattr(os, 'seteuid'):
            try:
                os.seteuid(self.original_euid)
                logger.debug(f"Restored privileges to UID {self.original_euid}")
            except Exception as e:
                logger.error(f"Failed to restore privileges: {e}")

class RateLimiter:
    """Rate limiter for controlling operation frequency"""
    
    def __init__(self, operations_per_second: float = 10.0):
        """
        Initialize the rate limiter
        
        Args:
            operations_per_second: Maximum operations per second
        """
        self.min_interval = 1.0 / operations_per_second
        self.last_operation_time = 0
    
    def wait(self):
        """Wait until next operation is allowed"""
        current_time = time.time()
        elapsed = current_time - self.last_operation_time
        
        if elapsed < self.min_interval:
            # Wait for remaining time
            time.sleep(self.min_interval - elapsed)
        
        self.last_operation_time = time.time()