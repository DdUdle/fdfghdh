"""
Wireless Network Analysis Framework - Device Database Module

This module maintains a database of device information, including OUI lookup,
vendor mapping, and behavioral fingerprinting for device categorization.
"""

import os
import json
import time
import logging
import hashlib
from typing import Dict, List, Optional, Set, Tuple, Union, Any

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

class DeviceDatabase:
    """
    Database for device identification and categorization based on MAC address OUIs,
    behavioral patterns, and historical observations.
    """
    
    def __init__(self, db_path: str = None):
        """
        Initialize the device database
        
        Args:
            db_path: Path to the database file (default: None, uses built-in path)
        """
        # Default paths
        self.db_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data')
        self.vendor_db_path = db_path or os.path.join(self.db_dir, 'vendor_db.json')
        self.device_info_path = os.path.join(self.db_dir, 'device_info.json')
        
        # Initialize data structures
        self.vendor_db = {}  # OUI -> vendor mapping
        self.device_info = {}  # MAC -> device info mapping
        self.category_signatures = {}  # Category -> signature mapping
        
        # Load existing data
        self.load_vendor_db()
        self.load_device_info()
    
    def load_vendor_db(self) -> bool:
        """
        Load vendor database from file
        
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            if os.path.exists(self.vendor_db_path):
                with open(self.vendor_db_path, 'r') as f:
                    self.vendor_db = json.load(f)
                logger.info(f"Loaded vendor database with {len(self.vendor_db)} entries")
                return True
            else:
                logger.warning(f"Vendor database file not found: {self.vendor_db_path}")
                
                # Initialize with some common vendors as fallback
                self.vendor_db = {
                    "000C29": "VMware",
                    "080027": "Oracle VirtualBox",
                    "00005E": "IANA",
                    "0050C2": "IEEE Registration Authority",
                    "001122": "Cisco Systems",
                    "001320": "Intel Corporate",
                    "001CF6": "Samsung Electronics Co.,Ltd",
                    "001D0F": "TP-LINK TECHNOLOGIES CO.,LTD.",
                    "002241": "Apple, Inc.",
                    "002547": "Apple, Inc.",
                    "002NOT": "Apple, Inc.",
                    "003065": "Apple, Inc.",
                    "0050C2": "IEEE Registration Authority",
                    "00E099": "Comtrol Europe, Ltd.",
                    "040CCE": "Apple, Inc.",
                    "044BED": "Apple, Inc.",
                    "080027": "PCS Computer Systems GmbH",
                    "0CD746": "Apple, Inc.",
                    "103025": "Apple, Inc.",
                    "18E7F4": "Apple, Inc.",
                    "24A074": "Apple, Inc.",
                    "28E02C": "Apple, Inc.",
                    "002241": "Apple, Inc.",
                    "002547": "Apple, Inc.",
                    "340387": "MediaTek Inc.",
                    "382C4A": "ASUSTek COMPUTER INC.",
                    "485AB6": "Huawei Technologies Co.,Ltd",
                    "503061": "Cisco Systems, Inc",
                    "6854FD": "Amazon Technologies Inc.",
                    "8CFDF0": "Qualcomm Inc.",
                    "984FEE": "Intel Corporate",
                    "B07FB9": "Netgear",
                    "B8C111": "Apple, Inc.",
                    "C02CD8": "Huawei Technologies Co.,Ltd",
                    "C8B373": "Cisco-Linksys, LLC",
                    "D0542D": "Cambridge Industries(Group) Co.,Ltd.",
                    "DC2B66": "InfoBLOCK S.A. de C.V.",
                    "EE6470": "Apple, Inc."
                }
                return False
                
        except Exception as e:
            logger.error(f"Error loading vendor database: {e}")
            self.vendor_db = {}
            return False
    
    def load_device_info(self) -> bool:
        """
        Load device information from file
        
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            if os.path.exists(self.device_info_path):
                with open(self.device_info_path, 'r') as f:
                    self.device_info = json.load(f)
                logger.info(f"Loaded device information for {len(self.device_info)} devices")
                return True
            else:
                logger.info("No device information file found, starting with empty database")
                self.device_info = {}
                return False
                
        except Exception as e:
            logger.error(f"Error loading device information: {e}")
            self.device_info = {}
            return False
    
    def save_device_info(self) -> bool:
        """
        Save device information to file
        
        Returns:
            bool: True if saved successfully, False otherwise
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.device_info_path), exist_ok=True)
            
            with open(self.device_info_path, 'w') as f:
                json.dump(self.device_info, f, indent=2)
            
            logger.info(f"Saved device information for {len(self.device_info)} devices")
            return True
            
        except Exception as e:
            logger.error(f"Error saving device information: {e}")
            return False
    
    def get_vendor(self, oui: str) -> str:
        """
        Get vendor name for an OUI
        
        Args:
            oui: OUI (first 3 bytes of MAC address)
            
        Returns:
            str: Vendor name or "Unknown" if not found
        """
        if not oui:
            return "Unknown"
        
        # Format OUI for lookup
        formatted_oui = oui.replace(':', '').replace('-', '').upper()
        
        # Try exact match first
        if formatted_oui in self.vendor_db:
            return self.vendor_db[formatted_oui]
        
        # Try first 6 chars
        if len(formatted_oui) >= 6:
            oui_prefix = formatted_oui[:6]
            if oui_prefix in self.vendor_db:
                return self.vendor_db[oui_prefix]
        
        return "Unknown"
    
    def categorize_device(self, mac_address: str) -> str:
        """
        Categorize a device based on MAC and available information
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            str: Device category
        """
        if not mac_address:
            return "UNKNOWN"
        
        # Check if we already have information for this device
        if mac_address in self.device_info:
            if 'category' in self.device_info[mac_address]:
                return self.device_info[mac_address]['category']
        
        # Extract OUI
        oui = mac_address.replace(':', '').replace('-', '').upper()[:6]
        
        # Get vendor
        vendor = self.get_vendor(oui)
        
        # Categorize based on vendor name
        category = "UNKNOWN"
        
        # Apple devices
        if any(keyword in vendor.upper() for keyword in ["APPLE", "IPHONE", "IPAD", "MACBOOK"]):
            category = "APPLE"
        
        # Microsoft devices
        elif any(keyword in vendor.upper() for keyword in ["MICROSOFT", "SURFACE"]):
            category = "MICROSOFT"
        
        # Samsung devices
        elif "SAMSUNG" in vendor.upper():
            category = "SAMSUNG"
        
        # Google devices
        elif any(keyword in vendor.upper() for keyword in ["GOOGLE", "ANDROID"]):
            category = "GOOGLE"
        
        # Network equipment
        elif any(keyword in vendor.upper() for keyword in 
               ["CISCO", "LINKSYS", "NETGEAR", "ARUBA", "UBIQUITI", "RUCKUS", 
                "JUNIPER", "MIKROTIK", "TP-LINK", "D-LINK", "HUAWEI"]):
            category = "NETWORK"
        
        # IoT devices
        elif any(keyword in vendor.upper() for keyword in 
               ["AMAZON", "NEST", "RING", "ECOBEE", "PHILIPS", "SONOS", 
                "BELKIN", "HONEYWELL", "ARLO"]):
            category = "IOT"
        
        # Virtual machines
        elif any(keyword in vendor.upper() for keyword in 
               ["VMWARE", "VIRTUALBOX", "HYPER-V", "XEN", "KVM"]):
            category = "VIRTUAL"
        
        # Store the categorization
        if mac_address not in self.device_info:
            self.device_info[mac_address] = {}
        
        self.device_info[mac_address]['category'] = category
        self.device_info[mac_address]['vendor'] = vendor
        self.device_info[mac_address]['oui'] = oui
        
        # Periodic save
        if len(self.device_info) % 10 == 0:
            self.save_device_info()
        
        return category
    
    def update_device_info(self, mac_address: str, info: Dict) -> bool:
        """
        Update information for a specific device
        
        Args:
            mac_address: Device MAC address
            info: Dictionary of device information
            
        Returns:
            bool: True if updated successfully, False otherwise
        """
        if not mac_address:
            return False
        
        try:
            # Initialize if not exist
            if mac_address not in self.device_info:
                self.device_info[mac_address] = {
                    'first_seen': time.time(),
                    'update_count': 0
                }
            
            # Update information
            for key, value in info.items():
                # Skip empty values
                if value is None or (isinstance(value, str) and not value):
                    continue
                    
                self.device_info[mac_address][key] = value
            
            # Update metadata
            self.device_info[mac_address]['last_updated'] = time.time()
            self.device_info[mac_address]['update_count'] = self.device_info[mac_address].get('update_count', 0) + 1
            
            # Periodic save
            if self.device_info[mac_address]['update_count'] % 5 == 0:
                self.save_device_info()
                
            return True
            
        except Exception as e:
            logger.error(f"Error updating device info for {mac_address}: {e}")
            return False
    
    def get_device_info(self, mac_address: str) -> Optional[Dict]:
        """
        Get information for a specific device
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            dict: Device information or None if not found
        """
        return self.device_info.get(mac_address)
    
    def get_devices_by_category(self, category: str) -> List[str]:
        """
        Get all devices of a specific category
        
        Args:
            category: Device category
            
        Returns:
            list: List of MAC addresses
        """
        return [
            mac for mac, info in self.device_info.items()
            if info.get('category') == category
        ]
    
    def get_devices_by_vendor(self, vendor: str) -> List[str]:
        """
        Get all devices from a specific vendor
        
        Args:
            vendor: Vendor name
            
        Returns:
            list: List of MAC addresses
        """
        return [
            mac for mac, info in self.device_info.items()
            if info.get('vendor') == vendor
        ]
    
    def calculate_signature(self, mac_address: str, capabilities: List[str]) -> str:
        """
        Calculate a unique signature for a device based on its capabilities
        
        Args:
            mac_address: Device MAC address
            capabilities: List of device capabilities
            
        Returns:
            str: Device signature
        """
        if not capabilities:
            return hashlib.md5(mac_address.encode()).hexdigest()[:12]
        
        # Sort capabilities for consistent signature
        sorted_caps = sorted(capabilities)
        signature_str = f"{mac_address}:{','.join(sorted_caps)}"
        
        return hashlib.md5(signature_str.encode()).hexdigest()[:12]
    
    def learn_category_signature(self, category: str, capabilities: List[str]):
        """
        Learn a new signature for a category
        
        Args:
            category: Device category
            capabilities: List of capabilities forming the signature
        """
        if not category or not capabilities:
            return
        
        if category not in self.category_signatures:
            self.category_signatures[category] = []
        
        # Sort capabilities for consistent signature
        sorted_caps = sorted(capabilities)
        signature = ','.join(sorted_caps)
        
        # Add if not already present
        if signature not in self.category_signatures[category]:
            self.category_signatures[category].append(signature)
    
    def match_signature_to_category(self, capabilities: List[str]) -> Optional[str]:
        """
        Match device capabilities to a known category signature
        
        Args:
            capabilities: List of device capabilities
            
        Returns:
            str: Matched category or None if no match
        """
        if not capabilities:
            return None
        
        # Sort capabilities for consistent matching
        sorted_caps = sorted(capabilities)
        device_sig = ','.join(sorted_caps)
        
        # Check for exact signature match
        for category, signatures in self.category_signatures.items():
            if device_sig in signatures:
                return category
        
        # Check for partial match (at least 80% overlap)
        device_cap_set = set(sorted_caps)
        best_match = None
        best_score = 0.0
        
        for category, signatures in self.category_signatures.items():
            for sig in signatures:
                sig_caps = set(sig.split(','))
                
                # Calculate Jaccard similarity
                if sig_caps and device_cap_set:
                    intersection = len(sig_caps.intersection(device_cap_set))
                    union = len(sig_caps.union(device_cap_set))
                    similarity = intersection / union
                    
                    if similarity > best_score and similarity >= 0.8:
                        best_score = similarity
                        best_match = category
        
        return best_match
    
    def export_database(self) -> Dict:
        """
        Export the entire database
        
        Returns:
            dict: Database contents
        """
        return {
            'vendor_db': self.vendor_db,
            'device_info': self.device_info,
            'category_signatures': self.category_signatures,
            'export_time': time.time()
        }
    
    def import_database(self, data: Dict) -> bool:
        """
        Import database from exported data
        
        Args:
            data: Exported database data
            
        Returns:
            bool: True if imported successfully, False otherwise
        """
        try:
            if 'vendor_db' in data:
                self.vendor_db = data['vendor_db']
            
            if 'device_info' in data:
                self.device_info = data['device_info']
            
            if 'category_signatures' in data:
                self.category_signatures = data['category_signatures']
            
            logger.info(f"Imported database with {len(self.device_info)} devices")
            return True
            
        except Exception as e:
            logger.error(f"Error importing database: {e}")
            return False