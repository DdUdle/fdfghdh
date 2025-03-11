"""
Unit tests for the Packet Crafter module
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import module to test
from framework.modules.packet_crafter import PacketCrafter

# Mock Scapy modules for testing without actual dependencies
sys.modules['scapy'] = MagicMock()
sys.modules['scapy.all'] = MagicMock()
sys.modules['scapy.layers.dot11'] = MagicMock()

class TestPacketCrafter(unittest.TestCase):
    """Test cases for PacketCrafter class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.crafter = PacketCrafter()
    
    def test_initialization(self):
        """Test initialization"""
        self.assertIsNotNone(self.crafter)
    
    @patch('framework.modules.packet_crafter.SCAPY_AVAILABLE', True)
    def test_extract_packet_info_valid(self):
        """Test extracting packet info with valid packet"""
        # Create mock packet
        mock_dot11 = MagicMock()
        mock_dot11.addr1 = "00:11:22:33:44:55"  # BSSID
        mock_dot11.addr2 = "AA:BB:CC:DD:EE:FF"  # Client
        mock_dot11.FCfield = 0x01  # To DS flag
        
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.getlayer.return_value = mock_dot11
        
        # Set channel in mock packet
        mock_packet.channel = 6
        
        # Test extraction
        client_mac, ap_mac, channel = self.crafter.extract_packet_info(mock_packet)
        
        # Verify correct values extracted
        self.assertEqual(client_mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(ap_mac, "00:11:22:33:44:55")
        self.assertEqual(channel, 6)
    
    @patch('framework.modules.packet_crafter.SCAPY_AVAILABLE', True)
    def test_extract_packet_info_invalid(self):
        """Test extracting packet info with invalid packet"""
        # Create mock packet without Dot11 layer
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False
        
        # Test extraction
        client_mac, ap_mac, channel = self.crafter.extract_packet_info(mock_packet)
        
        # Verify all values are None
        self.assertIsNone(client_mac)
        self.assertIsNone(ap_mac)
        self.assertIsNone(channel)
    
    @patch('framework.modules.packet_crafter.SCAPY_AVAILABLE', True)
    def test_get_packet_metadata(self):
        """Test getting packet metadata"""
        # Create mock packet
        mock_dot11 = MagicMock()
        mock_dot11.type = 0  # Management frame
        mock_dot11.subtype = 8  # Beacon
        mock_dot11.SC = 0x1234  # Sequence number
        
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.getlayer.return_value = mock_dot11
        mock_packet.dBm_AntSignal = -50  # Signal strength
        
        # Test metadata extraction
        metadata = self.crafter.get_packet_metadata(mock_packet)
        
        # Verify metadata
        self.assertEqual(metadata['packet_type'], 'beacon')
        self.assertEqual(metadata['signal_strength'], -50)
        self.assertEqual(metadata['sequence'], 0x1234 >> 4)
    
    @patch('framework.modules.packet_crafter.SCAPY_AVAILABLE', True)
    def test_craft_attack_packets_deauth(self):
        """Test crafting deauth packets"""
        # Mock craft method to return a placeholder packet
        self.crafter._craft_deauth_packet = MagicMock(return_value="deauth_packet")
        
        # Test packet creation
        ap_mac = "00:11:22:33:44:55"
        client_mac = "AA:BB:CC:DD:EE:FF"
        packets = self.crafter.craft_attack_packets(ap_mac, client_mac, 'deauth', 3, 7)
        
        # Verify 3 packets created
        self.assertEqual(len(packets), 3)
        self.assertEqual(packets[0], "deauth_packet")
        
        # Verify craft method called with correct parameters
        self.crafter._craft_deauth_packet.assert_called_with(ap_mac, client_mac, 7)
    
    @patch('framework.modules.packet_crafter.SCAPY_AVAILABLE', True)
    def test_craft_attack_packets_disassoc(self):
        """Test crafting disassoc packets"""
        # Mock craft method to return a placeholder packet
        self.crafter._craft_disassoc_packet = MagicMock(return_value="disassoc_packet")
        
        # Test packet creation
        ap_mac = "00:11:22:33:44:55"
        client_mac = "AA:BB:CC:DD:EE:FF"
        packets = self.crafter.craft_attack_packets(ap_mac, client_mac, 'disassoc', 2, 3)
        
        # Verify 2 packets created
        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0], "disassoc_packet")
        
        # Verify craft method called with correct parameters
        self.crafter._craft_disassoc_packet.assert_called_with(ap_mac, client_mac, 3)
    
    @patch('framework.modules.packet_crafter.SCAPY_AVAILABLE', True)
    def test_craft_attack_packets_mixed(self):
        """Test crafting mixed packets"""
        # Mock craft methods
        self.crafter._craft_deauth_packet = MagicMock(return_value="deauth_packet")
        self.crafter._craft_disassoc_packet = MagicMock(return_value="disassoc_packet")
        
        # Set random seed for predictable behavior
        import random
        random.seed(42)
        
        # Test packet creation
        ap_mac = "00:11:22:33:44:55"
        client_mac = "AA:BB:CC:DD:EE:FF"
        packets = self.crafter.craft_attack_packets(ap_mac, client_mac, 'mixed', 4, 7)
        
        # Verify 4 packets created with mixed types
        self.assertEqual(len(packets), 4)
    
    def test_generate_random_mac(self):
        """Test generating random MAC address"""
        # Test with no OUI
        mac = self.crafter.generate_random_mac()
        self.assertIsNotNone(mac)
        self.assertTrue(all(c in '0123456789ABCDEFabcdef:' for c in mac))
        self.assertEqual(len(mac), 17)  # XX:XX:XX:XX:XX:XX = 17 chars
        
        # Test with specified OUI
        mac = self.crafter.generate_random_mac(oui="00:11:22")
        self.assertTrue(mac.lower().startswith("00:11:22"))
    
    @patch('framework.modules.packet_crafter.sendp')
    def test_send_packet(self, mock_sendp):
        """Test sending packet"""
        # Set up mock
        mock_sendp.return_value = None
        
        # Test sending packet
        mock_packet = MagicMock()
        success = self.crafter.send_packet(mock_packet, "wlan0mon")
        
        # Verify sendp called with correct parameters
        mock_sendp.assert_called_once_with(mock_packet, iface="wlan0mon", verbose=False)
        self.assertTrue(success)
    
    @patch('framework.modules.packet_crafter.sendp')
    def test_send_packet_exception(self, mock_sendp):
        """Test sending packet with exception"""
        # Set up mock to raise exception
        mock_sendp.side_effect = Exception("Test exception")
        
        # Test sending packet
        mock_packet = MagicMock()
        success = self.crafter.send_packet(mock_packet, "wlan0mon")
        
        # Verify failure
        self.assertFalse(success)
    
    def test_scapy_unavailable(self):
        """Test behavior when Scapy is unavailable"""
        with patch('framework.modules.packet_crafter.SCAPY_AVAILABLE', False):
            # Create a new instance with Scapy unavailable
            crafter = PacketCrafter()
            
            # Test methods that require Scapy
            client_mac, ap_mac, channel = crafter.extract_packet_info(MagicMock())
            self.assertIsNone(client_mac)
            
            metadata = crafter.get_packet_metadata(MagicMock())
            self.assertEqual(metadata['packet_type'], 'unknown')
            
            packets = crafter.craft_attack_packets("", "", "", 1)
            self.assertEqual(len(packets), 0)

if __name__ == '__main__':
    unittest.main()