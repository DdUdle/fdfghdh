"""
Advanced Wireless Network Analysis Framework - Device Fingerprinting Module

This module analyzes wireless devices to determine their manufacturer, OS,
capabilities, and behavior patterns.
"""

import hashlib
import logging
import time
from typing import Dict, List, Set, Tuple, Optional, Union, Any

# Try to import Scapy for packet analysis
try:
    from scapy.all import Dot11, Dot11Elt
    from scapy.layers.dot11 import Dot11AssoReq, Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..utils.logging import setup_logger
from ..utils.device_db import DeviceDatabase
from ..core.constants import COMMON_OUIS, DEVICE_CATEGORIES

# Configure logger
logger = setup_logger(__name__)

class DeviceFingerprinter:
    """
    Fingerprints wireless devices based on their behavior, capabilities, and characteristics.
    """
    
    def __init__(self, device_db: DeviceDatabase = None):
        """
        Initialize the device fingerprinter
        
        Args:
            device_db: Device database for vendor lookups
        """
        self.device_db = device_db or DeviceDatabase()
        self.fingerprinted_devices = {}
        self.device_categories = {}
        
        # Feature extractors for fingerprinting
        self.feature_extractors = {
            'probe_request': self._extract_probe_request_features,
            'association_request': self._extract_association_request_features,
            'beacon': self._extract_beacon_features,
            'data': self._extract_data_features,
        }
    
    def is_fingerprinted(self, mac_address: str) -> bool:
        """
        Check if a device has already been fingerprinted
        
        Args:
            mac_address: MAC address of the device
            
        Returns:
            bool: True if the device has been fingerprinted
        """
        return mac_address in self.fingerprinted_devices
    
    def get_device_category(self, mac_address: str) -> str:
        """
        Get the category of a device
        
        Args:
            mac_address: MAC address of the device
            
        Returns:
            str: Device category or "DEFAULT" if unknown
        """
        return self.device_categories.get(mac_address, "DEFAULT")
    
    def get_device_fingerprint(self, mac_address: str) -> Optional[Dict]:
        """
        Get the fingerprint of a device
        
        Args:
            mac_address: MAC address of the device
            
        Returns:
            dict: Device fingerprint or None if not available
        """
        return self.fingerprinted_devices.get(mac_address)
    
    def fingerprint_device(self, packet: Any, mac_address: str) -> Optional[Dict]:
        """
        Analyze a packet to extract device fingerprinting information
        
        Args:
            packet: The packet to analyze
            mac_address: MAC address of the device
            
        Returns:
            dict: Device fingerprint or None if fingerprinting failed
        """
        if not SCAPY_AVAILABLE or not packet:
            return None
            
        try:
            # Create basic fingerprint structure
            fingerprint = {
                'mac_address': mac_address,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'oui': self._extract_oui(mac_address),
                'vendor': self._get_vendor(mac_address),
                'capabilities': set(),
                'protocols': set(),
                'pmf_detected': False,
                'features': {}
            }
            
            # Determine packet type for feature extraction
            packet_type = self._determine_packet_type(packet)
            
            # Extract features based on packet type
            if packet_type in self.feature_extractors:
                features = self.feature_extractors[packet_type](packet)
                if features:
                    fingerprint['features'].update(features)
            
            # Identify supported 802.11 protocols
            self._identify_protocols(packet, fingerprint)
            
            # Detect PMF (Protected Management Frames) support
            self._detect_pmf_support(packet, fingerprint)
            
            # Assign to device category
            category = self._determine_device_category(fingerprint)
            fingerprint['category'] = category
            self.device_categories[mac_address] = category
            
            # Calculate unique hash for this device
            fingerprint_str = f"{mac_address}:{fingerprint['vendor']}:{','.join(sorted(fingerprint['capabilities']))}"
            fingerprint['hash'] = hashlib.md5(fingerprint_str.encode()).hexdigest()[:12]
            
            # Store the fingerprint
            self.fingerprinted_devices[mac_address] = fingerprint
            logger.debug(f"Device {mac_address} fingerprinted: {category} - {fingerprint['vendor']}")
            
            return fingerprint
            
        except Exception as e:
            logger.error(f"Error fingerprinting device {mac_address}: {e}")
            return None
    
    def _determine_packet_type(self, packet: Any) -> str:
        """
        Determine the type of packet for feature extraction
        
        Args:
            packet: The packet to analyze
            
        Returns:
            str: Packet type identifier
        """
        if not packet.haslayer(Dot11):
            return 'unknown'
            
        dot11 = packet.getlayer(Dot11)
        
        # Categorize based on 802.11 type and subtype
        if dot11.type == 0:  # Management
            if dot11.subtype == 0:  # Association Request
                return 'association_request'
            elif dot11.subtype == 4:  # Probe Request
                return 'probe_request'
            elif dot11.subtype == 5:  # Probe Response
                return 'probe_response'
            elif dot11.subtype == 8:  # Beacon
                return 'beacon'
            else:
                return 'management'
        elif dot11.type == 2:  # Data
            return 'data'
        else:
            return 'unknown'
    
    def _extract_probe_request_features(self, packet: Any) -> Dict:
        """
        Extract features from a probe request packet
        
        Args:
            packet: The packet to analyze
            
        Returns:
            dict: Extracted features
        """
        features = {}
        
        # Only process if this is a probe request
        if not (packet.haslayer(Dot11) and packet.getlayer(Dot11).subtype == 4):
            return features
            
        try:
            # Extract SSID if present
            ssid = None
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
                features['probed_ssid'] = ssid
                
            # Check for directed probe (specific SSID) vs. broadcast probe (null SSID)
            if ssid == '':
                features['broadcast_probe'] = True
            else:
                features['directed_probe'] = True
                
            # Extract supported rates
            supported_rates = []
            for element in packet.iterpayloads():
                if hasattr(element, 'ID') and element.ID == 1 and hasattr(element, 'info'):
                    supported_rates = [int(b) & 0x7F for b in element.info]
                    features['supported_rates'] = supported_rates
                    break
            
            # Extract WPS information if present
            for element in packet.iterpayloads():
                if (hasattr(element, 'ID') and element.ID == 221 and 
                    hasattr(element, 'info') and len(element.info) >= 4):
                    # Check if this is a WPS IE (Microsoft OUI + type 4)
                    if element.info[:3] == b'\x00\x50\xF2' and element.info[3] == 4:
                        features['wps_supported'] = True
                        break
            
            # Extract vendor specific IEs to identify device
            vendor_elements = []
            for element in packet.iterpayloads():
                if (hasattr(element, 'ID') and element.ID == 221 and 
                    hasattr(element, 'info') and len(element.info) >= 3):
                    vendor_oui = element.info[:3].hex()
                    vendor_elements.append(vendor_oui)
            
            if vendor_elements:
                features['vendor_elements'] = vendor_elements
        
        except Exception as e:
            logger.error(f"Error extracting probe request features: {e}")
        
        return features
    
    def _extract_association_request_features(self, packet: Any) -> Dict:
        """
        Extract features from an association request packet
        
        Args:
            packet: The packet to analyze
            
        Returns:
            dict: Extracted features
        """
        features = {}
        
        # Only process if this is an association request
        if not (packet.haslayer(Dot11) and packet.getlayer(Dot11).subtype == 0):
            return features
            
        try:
            # Extract capabilities field
            if packet.haslayer(Dot11AssoReq) and hasattr(packet[Dot11AssoReq], 'cap'):
                cap_field = packet[Dot11AssoReq].cap
                
                features['capability_short_preamble'] = bool(cap_field & 0x0020)
                features['capability_pbcc'] = bool(cap_field & 0x0040)
                features['capability_channel_agility'] = bool(cap_field & 0x0080)
                features['capability_short_slot'] = bool(cap_field & 0x0400)
                features['capability_dsss_ofdm'] = bool(cap_field & 0x2000)
                
                # Extract capability bytes for fingerprinting
                features['capability_bytes'] = cap_field
            
            # Extract HT Capabilities if present (802.11n)
            for element in packet.iterpayloads():
                if hasattr(element, 'ID') and element.ID == 45 and hasattr(element, 'info'):
                    features['supports_11n'] = True
                    if len(element.info) >= 2:
                        ht_cap = int.from_bytes(element.info[:2], byteorder='little')
                        features['ht_capabilities'] = ht_cap
                        features['supports_greenfield'] = bool(ht_cap & 0x0010)
                        features['supports_40mhz'] = bool(ht_cap & 0x0002)
                    break
            
            # Extract VHT Capabilities if present (802.11ac)
            for element in packet.iterpayloads():
                if hasattr(element, 'ID') and element.ID == 191 and hasattr(element, 'info'):
                    features['supports_11ac'] = True
                    break
            
            # Extract HE Capabilities if present (802.11ax)
            for element in packet.iterpayloads():
                if (hasattr(element, 'ID') and element.ID == 255 and 
                    hasattr(element, 'info') and len(element.info) >= 2):
                    # Check if this is an HE (802.11ax) capabilities IE
                    if element.info[0] == 35:  # HE Capabilities extension ID
                        features['supports_11ax'] = True
                        break
        
        except Exception as e:
            logger.error(f"Error extracting association request features: {e}")
        
        return features
    
    def _extract_beacon_features(self, packet: Any) -> Dict:
        """
        Extract features from a beacon packet
        
        Args:
            packet: The packet to analyze
            
        Returns:
            dict: Extracted features
        """
        features = {}
        
        # Only process if this is a beacon
        if not (packet.haslayer(Dot11) and packet.getlayer(Dot11).subtype == 8):
            return features
            
        try:
            # Extract SSID
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
                features['ssid'] = ssid
            
            # Extract RSN (Robust Security Network) information
            for element in packet.iterpayloads():
                if hasattr(element, 'ID') and element.ID == 48 and hasattr(element, 'info'):
                    features['rsn_present'] = True
                    
                    # Parse RSN info - at least version (2 bytes) and group cipher (4 bytes)
                    if len(element.info) >= 6:
                        version = int.from_bytes(element.info[:2], byteorder='little')
                        features['rsn_version'] = version
                        
                        group_cipher_oui = element.info[2:5].hex()
                        group_cipher_type = element.info[5]
                        features['group_cipher'] = f"{group_cipher_oui}:{group_cipher_type}"
                        
                        # Check for PMF capabilities (if long enough to include RSN capabilities)
                        if len(element.info) >= 8:
                            capabilities = int.from_bytes(element.info[-2:], byteorder='little')
                            features['mfp_capable'] = bool(capabilities & 0x40)  # MFP capable
                            features['mfp_required'] = bool(capabilities & 0x80)  # MFP required
                    break
        
        except Exception as e:
            logger.error(f"Error extracting beacon features: {e}")
        
        return features
    
    def _extract_data_features(self, packet: Any) -> Dict:
        """
        Extract features from a data packet
        
        Args:
            packet: The packet to analyze
            
        Returns:
            dict: Extracted features
        """
        features = {}
        
        # Only process if this is a data packet
        if not (packet.haslayer(Dot11) and packet.getlayer(Dot11).type == 2):
            return features
            
        try:
            # Extract QoS information if present
            qos_present = packet.getlayer(Dot11).subtype >= 8 and packet.getlayer(Dot11).subtype <= 11
            features['qos_enabled'] = qos_present
            
            # Extract Power Management bit
            if hasattr(packet.getlayer(Dot11), 'FCfield'):
                pwr_mgt = bool(packet.getlayer(Dot11).FCfield & 0x10)
                features['power_save_mode'] = pwr_mgt
        
        except Exception as e:
            logger.error(f"Error extracting data packet features: {e}")
        
        return features
    
    def _extract_oui(self, mac_address: str) -> str:
        """
        Extract the OUI (Organizationally Unique Identifier) from a MAC address
        
        Args:
            mac_address: MAC address string
            
        Returns:
            str: OUI part of the MAC address
        """
        if not mac_address or len(mac_address) < 8:
            return ""
        
        parts = mac_address.split(':')
        if len(parts) >= 3:
            return ''.join(parts[:3]).upper()
        
        # Alternative format using dashes
        parts = mac_address.split('-')
        if len(parts) >= 3:
            return ''.join(parts[:3]).upper()
        
        # Straight string format
        return mac_address.replace(':', '').replace('-', '').upper()[:6]
    
    def _get_vendor(self, mac_address: str) -> str:
        """
        Get the vendor name for a MAC address
        
        Args:
            mac_address: MAC address string
            
        Returns:
            str: Vendor name or "Unknown"
        """
        oui = self._extract_oui(mac_address)
        if not oui:
            return "Unknown"
        
        # Look up in vendor database
        if self.device_db and hasattr(self.device_db, 'get_vendor'):
            vendor = self.device_db.get_vendor(oui)
            if vendor:
                return vendor
        
        # Check common OUIs
        for vendor, ouis in COMMON_OUIS.items():
            if oui in [self._extract_oui(o) for o in ouis]:
                return vendor
        
        return "Unknown"
    
    def _identify_protocols(self, packet: Any, fingerprint: Dict):
        """
        Identify supported 802.11 protocols
        
        Args:
            packet: The packet to analyze
            fingerprint: Fingerprint dictionary to update
        """
        try:
            # Look for protocol-specific information elements
            for element in packet.iterpayloads():
                if hasattr(element, 'ID'):
                    # HT Capabilities (802.11n)
                    if element.ID == 45:
                        fingerprint['capabilities'].add('802.11n')
                        fingerprint['protocols'].add('n')
                    
                    # VHT Capabilities (802.11ac)
                    elif element.ID == 191:
                        fingerprint['capabilities'].add('802.11ac')
                        fingerprint['protocols'].add('ac')
                    
                    # HE Capabilities (802.11ax)
                    elif element.ID == 255 and hasattr(element, 'info') and len(element.info) >= 1:
                        if element.info[0] == 35:  # HE Capabilities extension ID
                            fingerprint['capabilities'].add('802.11ax')
                            fingerprint['protocols'].add('ax')
                    
                    # WPA/RSN elements
                    elif element.ID == 48:  # RSN
                        fingerprint['capabilities'].add('WPA2')
                    elif element.ID == 221 and hasattr(element, 'info') and len(element.info) >= 4:
                        if element.info[:3] == b'\x00\x50\xF2' and element.info[3] == 1:
                            fingerprint['capabilities'].add('WPA')
        
        except Exception as e:
            logger.error(f"Error identifying protocols: {e}")
    
    def _detect_pmf_support(self, packet: Any, fingerprint: Dict):
        """
        Detect support for Protected Management Frames (PMF)
        
        Args:
            packet: The packet to analyze
            fingerprint: Fingerprint dictionary to update
        """
        try:
            # Look for RSN element with PMF capabilities
            for element in packet.iterpayloads():
                if (hasattr(element, 'ID') and element.ID == 48 and  # RSN element
                    hasattr(element, 'info') and len(element.info) >= 8):
                    
                    # RSN Capabilities field is in the last 2 bytes
                    capabilities = int.from_bytes(element.info[-2:], byteorder='little')
                    
                    # Check bit 6 (MFP capable) and bit 7 (MFP required)
                    mfp_capable = bool(capabilities & 0x40)
                    mfp_required = bool(capabilities & 0x80)
                    
                    if mfp_capable or mfp_required:
                        fingerprint['capabilities'].add('PMF')
                        fingerprint['pmf_detected'] = True
                        if mfp_required:
                            fingerprint['capabilities'].add('PMF_required')
                    break
        
        except Exception as e:
            logger.error(f"Error detecting PMF support: {e}")
    
    def _determine_device_category(self, fingerprint: Dict) -> str:
        """
        Determine the device category based on fingerprint information
        
        Args:
            fingerprint: Device fingerprint
            
        Returns:
            str: Device category
        """
        vendor = fingerprint.get('vendor', '').upper()
        
        # Categorize based on vendor name
        if vendor:
            if any(keyword in vendor for keyword in ["APPLE", "IPHONE", "MACBOOK", "IPAD"]):
                return "APPLE"
            elif any(keyword in vendor for keyword in ["SAMSUNG", "GALAXY"]):
                return "SAMSUNG"
            elif any(keyword in vendor for keyword in ["MICROSOFT", "SURFACE"]):
                return "MICROSOFT"
            elif any(keyword in vendor for keyword in ["INTEL", "CENTRINO"]):
                return "INTEL"
            elif any(keyword in vendor for keyword in ["GOOGLE", "PIXEL", "ANDROID"]):
                return "GOOGLE"
            elif any(keyword in vendor for keyword in ["HUAWEI", "HONOR"]):
                return "HUAWEI"
            elif any(keyword in vendor for keyword in ["NOKIA", "HMD"]):
                return "NOKIA"
            elif any(keyword in vendor for keyword in ["LG", "ELECTRONICS"]):
                return "LG"
            elif any(keyword in vendor for keyword in ["SONY", "XPERIA"]):
                return "SONY"
            elif any(keyword in vendor for keyword in ["HTC"]):
                return "HTC"
            elif any(keyword in vendor for keyword in ["MOTOROLA", "MOTO"]):
                return "MOTOROLA"
            elif any(keyword in vendor for keyword in ["ONEPLUS"]):
                return "ONEPLUS"
            elif any(keyword in vendor for keyword in ["XIAOMI", "REDMI"]):
                return "XIAOMI"
            elif any(keyword in vendor for keyword in ["OPPO", "REALME"]):
                return "OPPO"
            elif any(keyword in vendor for keyword in ["ASUS", "REPUBLIC OF GAMERS"]):
                return "ASUS"
            elif any(keyword in vendor for keyword in ["LENOVO"]):
                return "LENOVO"
            elif any(keyword in vendor for keyword in ["DELL"]):
                return "DELL"
            elif any(keyword in vendor for keyword in ["HP", "HEWLETT"]):
                return "HP"
            elif any(keyword in vendor for keyword in ["ACER"]):
                return "ACER"
            elif any(keyword in vendor for keyword in ["TOSHIBA"]):
                return "TOSHIBA"
        
        # Check OUI against known lists
        oui = fingerprint.get('oui', '')
        for category, ouis in COMMON_OUIS.items():
            if oui in [self._extract_oui(o) for o in ouis]:
                return category
        
        # Fallback to protocol-based categorization
        protocols = fingerprint.get('protocols', set())
        if 'ax' in protocols:
            return "MODERN"
        elif 'ac' in protocols:
            return "RECENT"
        
        return "DEFAULT"