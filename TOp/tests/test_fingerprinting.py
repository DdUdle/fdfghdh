"""
Unit tests for the Device Fingerprinting module
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, Mock

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock Scapy modules for testing
sys.modules['scapy'] = MagicMock()
sys.modules['scapy.all'] = MagicMock()
sys.modules['scapy.layers.dot11'] = MagicMock()

# Import module to test
from framework.modules.fingerprinting import DeviceFingerprinter

class TestDeviceFingerprinter(unittest.TestCase):
    """Test cases for DeviceFingerprinter class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_device_db = MagicMock()
        self.mock_device_db.get_vendor.return_value = "Test Vendor"
        
        with patch('framework.modules.fingerprinting.SCAPY_AVAILABLE', True):
            self.fingerprinter = DeviceFingerprinter(self.mock_device_db)
    
    def test_initialization(self):
        """Test initialization"""
        self.assertIsNotNone(self.fingerprinter)
        self.assertEqual(self.fingerprinter.device_db, self.mock_device_db)
        self.assertEqual(len(self.fingerprinter.fingerprinted_devices), 0)
    
    def test_is_fingerprinted(self):
        """Test checking if device is fingerprinted"""
        # Not fingerprinted initially
        self.assertFalse(self.fingerprinter.is_fingerprinted("00:11:22:33:44:55"))
        
        # Add a fingerprinted device
        self.fingerprinter.fingerprinted_devices["00:11:22:33:44:55"] = {"test": "data"}
        
        # Now it should be fingerprinted
        self.assertTrue(self.fingerprinter.is_fingerprinted("00:11:22:33:44:55"))
    
    def test_get_device_category(self):
        """Test getting device category"""
        # Unknown device
        self.assertEqual(self.fingerprinter.get_device_category("00:11:22:33:44:55"), "DEFAULT")
        
        # Add a categorized device
        self.fingerprinter.device_categories["00:11:22:33:44:55"] = "APPLE"
        
        # Now category should be returned
        self.assertEqual(self.fingerprinter.get_device_category("00:11:22:33:44:55"), "APPLE")
    
    def test_get_device_fingerprint(self):
        """Test getting device fingerprint"""
        # Unknown device
        self.assertIsNone(self.fingerprinter.get_device_fingerprint("00:11:22:33:44:55"))
        
        # Add a fingerprinted device
        test_data = {"vendor": "Apple", "category": "APPLE"}
        self.fingerprinter.fingerprinted_devices["00:11:22:33:44:55"] = test_data
        
        # Now fingerprint should be returned
        self.assertEqual(self.fingerprinter.get_device_fingerprint("00:11:22:33:44:55"), test_data)
    
    def test_extract_oui(self):
        """Test OUI extraction"""
        # Test with colons
        self.assertEqual(self.fingerprinter._extract_oui("00:11:22:33:44:55"), "001122")
        
        # Test with dashes
        self.assertEqual(self.fingerprinter._extract_oui("00-11-22-33-44-55"), "001122")
        
        # Test with no separators
        self.assertEqual(self.fingerprinter._extract_oui("001122334455"), "001122")
        
        # Test with invalid input
        self.assertEqual(self.fingerprinter._extract_oui(""), "")
        self.assertEqual(self.fingerprinter._extract_oui(None), "")
    
    def test_get_vendor(self):
        """Test vendor lookup"""
        # Mock device_db.get_vendor to return specific values
        self.mock_device_db.get_vendor.side_effect = lambda oui: {
            "001122": "Apple Inc.",
            "AABBCC": "Google LLC",
            "UNKNOWN": None
        }.get(oui, "Unknown")
        
        # Test vendor lookup
        self.assertEqual(self.fingerprinter._get_vendor("00:11:22:33:44:55"), "Apple Inc.")
        self.assertEqual(self.fingerprinter._get_vendor("AA:BB:CC:DD:EE:FF"), "Google LLC")
        self.assertEqual(self.fingerprinter._get_vendor("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"), "Unknown")
    
    @patch('framework.modules.fingerprinting.SCAPY_AVAILABLE', True)
    def test_determine_packet_type(self):
        """Test packet type determination"""
        # Create mock packets
        mock_assoc_req = MagicMock()
        mock_assoc_req.haslayer.return_value = True
        mock_dot11_assoc = MagicMock()
        mock_dot11_assoc.type = 0  # Management
        mock_dot11_assoc.subtype = 0  # Association Request
        mock_assoc_req.getlayer.return_value = mock_dot11_assoc
        
        mock_probe_req = MagicMock()
        mock_probe_req.haslayer.return_value = True
        mock_dot11_probe = MagicMock()
        mock_dot11_probe.type = 0  # Management
        mock_dot11_probe.subtype = 4  # Probe Request
        mock_probe_req.getlayer.return_value = mock_dot11_probe
        
        mock_beacon = MagicMock()
        mock_beacon.haslayer.return_value = True
        mock_dot11_beacon = MagicMock()
        mock_dot11_beacon.type = 0  # Management
        mock_dot11_beacon.subtype = 8  # Beacon
        mock_beacon.getlayer.return_value = mock_dot11_beacon
        
        mock_data = MagicMock()
        mock_data.haslayer.return_value = True
        mock_dot11_data = MagicMock()
        mock_dot11_data.type = 2  # Data
        mock_dot11_data.subtype = 0  # Data
        mock_data.getlayer.return_value = mock_dot11_data
        
        # Test packet type determination
        self.assertEqual(self.fingerprinter._determine_packet_type(mock_assoc_req), 'association_request')
        self.assertEqual(self.fingerprinter._determine_packet_type(mock_probe_req), 'probe_request')
        self.assertEqual(self.fingerprinter._determine_packet_type(mock_beacon), 'beacon')
        self.assertEqual(self.fingerprinter._determine_packet_type(mock_data), 'data')
        
        # Test with no Dot11 layer
        mock_no_dot11 = MagicMock()
        mock_no_dot11.haslayer.return_value = False
        self.assertEqual(self.fingerprinter._determine_packet_type(mock_no_dot11), 'unknown')
    
    @patch('framework.modules.fingerprinting.SCAPY_AVAILABLE', True)
    def test_fingerprint_device_basic(self):
        """Test basic device fingerprinting"""
        # Create a mock packet with basic info
        mock_dot11 = MagicMock()
        mock_dot11.type = 0  # Management
        mock_dot11.subtype = 4  # Probe Request
        
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.getlayer.return_value = mock_dot11
        
        # Create mock elements for iteration
        mock_packet.iterpayloads.return_value = []
        
        # Test fingerprinting
        mac_address = "00:11:22:33:44:55"
        fingerprint = self.fingerprinter.fingerprint_device(mock_packet, mac_address)
        
        # Verify fingerprint
        self.assertIsNotNone(fingerprint)
        self.assertEqual(fingerprint['mac_address'], mac_address)
        self.assertEqual(fingerprint['vendor'], "Test Vendor")
        self.assertEqual(fingerprint['oui'], "001122")
        self.assertFalse(fingerprint['pmf_detected'])
        
        # Verify device is now in fingerprinted devices
        self.assertTrue(mac_address in self.fingerprinter.fingerprinted_devices)
    
    @patch('framework.modules.fingerprinting.SCAPY_AVAILABLE', False)
    def test_fingerprint_device_scapy_unavailable(self):
        """Test fingerprinting when Scapy is unavailable"""
        # Create a new fingerprinter instance with Scapy unavailable
        fingerprinter = DeviceFingerprinter(self.mock_device_db)
        
        # Attempt fingerprinting
        fingerprint = fingerprinter.fingerprint_device(MagicMock(), "00:11:22:33:44:55")
        
        # Verify None is returned
        self.assertIsNone(fingerprint)
    
    @patch('framework.modules.fingerprinting.SCAPY_AVAILABLE', True)
    def test_detect_pmf_support(self):
        """Test PMF support detection"""
        # Create a mock fingerprint
        fingerprint = {
            'capabilities': set(),
            'pmf_detected': False
        }
        
        # Create a mock packet with RSN element
        mock_rsn = MagicMock()
        mock_rsn.ID = 48  # RSN element
        mock_rsn.info = bytes([1, 0] + [0] * 4 + [0, 0xC0])  # Last 2 bytes with MFP bits set
        
        mock_packet = MagicMock()
        mock_packet.iterpayloads.return_value = [mock_rsn]
        
        # Test PMF detection
        self.fingerprinter._detect_pmf_support(mock_packet, fingerprint)
        
        # Verify PMF detected
        self.assertTrue(fingerprint['pmf_detected'])
        self.assertIn('PMF', fingerprint['capabilities'])
        self.assertIn('PMF_required', fingerprint['capabilities'])
    
    def test_determine_device_category(self):
        """Test device categorization"""
        # Test various vendor names
        test_cases = [
            {'vendor': 'Apple Inc.', 'expected': 'APPLE'},
            {'vendor': 'iPhone', 'expected': 'APPLE'},
            {'vendor': 'Samsung Electronics', 'expected': 'SAMSUNG'},
            {'vendor': 'Microsoft', 'expected': 'MICROSOFT'},
            {'vendor': 'Google LLC', 'expected': 'GOOGLE'},
            {'vendor': 'Unknown Vendor', 'expected': 'DEFAULT'}
        ]
        
        for case in test_cases:
            fingerprint = {'vendor': case['vendor']}
            category = self.fingerprinter._determine_device_category(fingerprint)
            self.assertEqual(category, case['expected'], f"Failed for vendor: {case['vendor']}")
    
    def test_calculate_signature(self):
        """Test device signature calculation"""
        # Test with capabilities
        fingerprint = {'mac_address': '00:11:22:33:44:55', 'capabilities': ['WPA2', 'PMF', 'WMM']}
        signature = self.fingerprinter.calculate_signature(fingerprint['mac_address'], fingerprint['capabilities'])
        
        # Test uniqueness
        fingerprint2 = {'mac_address': '00:11:22:33:44:55', 'capabilities': ['PMF', 'WPA2', 'WMM']}  # Different order
        signature2 = self.fingerprinter.calculate_signature(fingerprint2['mac_address'], fingerprint2['capabilities'])
        
        # Different capabilities
        fingerprint3 = {'mac_address': '00:11:22:33:44:55', 'capabilities': ['WPA2', 'PMF']}  # Missing WMM
        signature3 = self.fingerprinter.calculate_signature(fingerprint3['mac_address'], fingerprint3['capabilities'])
        
        # Verify signatures
        self.assertEqual(signature, signature2)  # Order shouldn't matter
        self.assertNotEqual(signature, signature3)  # Different capabilities = different signature
    
    def test_learn_category_signature(self):
        """Test learning category signatures"""
        category = "APPLE"
        capabilities = ['WPA2', 'PMF', '802.11n']
        
        # Learn signature
        self.fingerprinter.learn_category_signature(category, capabilities)
        
        # Verify signature learned
        self.assertIn(category, self.fingerprinter.category_signatures)
        self.assertIn(','.join(sorted(capabilities)), self.fingerprinter.category_signatures[category])
        
        # Learn another signature for same category
        capabilities2 = ['WPA2', 'PMF', '802.11ac']
        self.fingerprinter.learn_category_signature(category, capabilities2)
        
        # Verify both signatures present
        self.assertEqual(len(self.fingerprinter.category_signatures[category]), 2)
    
    def test_match_signature_to_category(self):
        """Test matching capabilities to category signatures"""
        # Set up signatures
        self.fingerprinter.category_signatures = {
            'APPLE': [
                'PMF,WPA2,802.11ac',
                'PMF,WPA2,802.11n'
            ],
            'SAMSUNG': [
                'WPA2,802.11n',
                'WPA,802.11n'
            ]
        }
        
        # Test exact match
        capabilities1 = ['PMF', 'WPA2', '802.11ac']
        match1 = self.fingerprinter.match_signature_to_category(capabilities1)
        self.assertEqual(match1, 'APPLE')
        
        # Test partial match
        capabilities2 = ['PMF', 'WPA2', '802.11ac', 'WMM']  # Added WMM
        match2 = self.fingerprinter.match_signature_to_category(capabilities2)
        self.assertEqual(match2, 'APPLE')
        
        # Test no match
        capabilities3 = ['WPA', 'WPS']
        match3 = self.fingerprinter.match_signature_to_category(capabilities3)
        self.assertIsNone(match3)

if __name__ == '__main__':
    unittest.main()