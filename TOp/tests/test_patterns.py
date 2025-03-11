"""
Unit tests for the Temporal Pattern Mining module
"""

import os
import sys
import time
import unittest
from unittest.mock import patch, MagicMock, Mock

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import module to test
from framework.ai.pattern_miner import TemporalPatternMiner

# Mock numpy for testing
sys.modules['numpy'] = MagicMock()

class TestTemporalPatternMiner(unittest.TestCase):
    """Test cases for TemporalPatternMiner class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.miner = TemporalPatternMiner(max_history=100, max_pattern_length=5)
        
        # Set up some test data
        self.client_mac = "00:11:22:33:44:55"
        self.current_time = time.time()
    
    def test_initialization(self):
        """Test initialization"""
        self.assertIsNotNone(self.miner)
        self.assertEqual(self.miner.max_history, 100)
        self.assertEqual(self.miner.max_pattern_length, 5)
        self.assertEqual(len(self.miner.client_activity), 0)
    
    def test_record_activity(self):
        """Test recording client activity"""
        # Record activities
        activities = [
            ('probe_request', {}),
            ('association_request', {}),
            ('data', {'size': 100}),
            ('deauthentication', {'reason': 7})
        ]
        
        # Record each activity with increasing timestamps
        for i, (activity_type, metadata) in enumerate(activities):
            timestamp = self.current_time + i * 60  # 1 minute apart
            self.miner.record_activity(self.client_mac, timestamp, activity_type, metadata)
        
        # Verify activities recorded
        self.assertIn(self.client_mac, self.miner.client_activity)
        self.assertEqual(len(self.miner.client_activity[self.client_mac]), 4)
        
        # Verify activity types recorded
        self.assertIn(self.client_mac, self.miner.activity_types)
        self.assertEqual(len(self.miner.activity_types[self.client_mac]), 4)
        for activity_type, _ in activities:
            self.assertIn(activity_type, self.miner.activity_types[self.client_mac])
        
        # Verify time intervals recorded for repeated activity
        # Add another probe request
        self.miner.record_activity(self.client_mac, self.current_time + 300, 'probe_request', {})
        probe_intervals = self.miner.time_intervals.get(f"{self.client_mac}:probe_request", [])
        self.assertEqual(len(probe_intervals), 1)
        self.assertAlmostEqual(probe_intervals[0], 300)  # 300 seconds between probe requests
    
    def test_record_activity_limit(self):
        """Test activity history limit"""
        # Record many activities
        for i in range(150):  # More than max_history
            self.miner.record_activity(self.client_mac, self.current_time + i, 'data', {})
        
        # Verify history limited to max_history
        self.assertEqual(len(self.miner.client_activity[self.client_mac]), 100)
        
        # Verify oldest activities were dropped
        first_activity = self.miner.client_activity[self.client_mac][0]
        self.assertAlmostEqual(first_activity['timestamp'], self.current_time + 50)
    
    def test_record_channel_change(self):
        """Test recording channel changes"""
        # Record channel changes
        mac_address = "00:11:22:33:44:55"
        
        # String channel numbers
        self.miner.record_channel_change(mac_address, "1", "6", self.current_time)
        
        # Integer channel numbers
        self.miner.record_channel_change(mac_address, 6, 11, self.current_time + 60)
        
        # Invalid channel (should be skipped)
        self.miner.record_channel_change(mac_address, "invalid", 1, self.current_time + 120)
        
        # Verify channel changes recorded
        self.assertIn(mac_address, self.miner.channel_patterns)
        self.assertEqual(len(self.miner.channel_patterns[mac_address]), 2)
        
        # Verify channel converted to integer
        first_change = self.miner.channel_patterns[mac_address][0]
        self.assertEqual(first_change['old_channel'], 1)
        self.assertEqual(first_change['new_channel'], 6)
    
    def test_analyze_patterns_insufficient_data(self):
        """Test analyzing patterns with insufficient data"""
        # No data
        result = self.miner.analyze_patterns(self.client_mac)
        self.assertEqual(result['status'], 'insufficient_data')
        
        # Some data but not enough
        for i in range(3):  # Less than 5 required
            self.miner.record_activity(self.client_mac, self.current_time + i, 'data', {})
        
        result = self.miner.analyze_patterns(self.client_mac)
        self.assertEqual(result['status'], 'insufficient_data')
    
    def test_analyze_patterns_sufficient_data(self):
        """Test analyzing patterns with sufficient data"""
        # Add enough activities
        for i in range(10):
            self.miner.record_activity(self.client_mac, self.current_time + i * 60, 
                                     ['data', 'probe_request', 'beacon'][i % 3], {})
        
        # Also add reconnect data
        self.miner.record_activity(self.client_mac, self.current_time + 600,
                                 'reconnected', {'time': 5.5})
        
        # Analyze patterns
        result = self.miner.analyze_patterns(self.client_mac)
        
        # Verify analysis result
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['client'], self.client_mac)
        self.assertEqual(result['activity_count'], 11)
        self.assertIn('behavior_type', result)
        self.assertIn('activity_distribution', result)
        self.assertEqual(result['data_quality'], 'medium')
    
    def test_get_optimal_attack_timing_immediate(self):
        """Test getting optimal attack timing with immediate recommendation"""
        # No data
        timing = self.miner.get_optimal_attack_timing(self.client_mac)
        self.assertEqual(timing['recommendation'], 'immediate')
        
        # Some data but no clear pattern
        for i in range(7):
            # Random activities at irregular intervals
            self.miner.record_activity(self.client_mac, self.current_time + i * 123,
                                     ['data', 'probe_request', 'beacon'][i % 3], {})
        
        timing = self.miner.get_optimal_attack_timing(self.client_mac)
        # Default should still be immediate without clear patterns
        self.assertEqual(timing['recommendation'], 'immediate')
    
    def test_get_optimal_attack_timing_delayed(self):
        """Test getting optimal attack timing with delayed recommendation"""
        # Add a recent disconnection
        self.miner.record_activity(self.client_mac, time.time() - 5,
                                 'deauthentication', {'reason': 7})
        
        # Get timing
        timing = self.miner.get_optimal_attack_timing(self.client_mac)
        
        # Should recommend delay after recent disconnection
        self.assertEqual(timing['recommendation'], 'delayed')
        self.assertGreater(timing['delay'], 0)
        self.assertEqual(timing['reason'], 'recent_disconnection')
    
    def test_predict_channel_changes_insufficient_data(self):
        """Test predicting channel changes with insufficient data"""
        # No data
        result = self.miner.predict_channel_changes(self.client_mac)
        self.assertEqual(result['status'], 'insufficient_data')
        
        # Add some data but not enough
        self.miner.record_channel_change(self.client_mac, 1, 6, self.current_time)
        self.miner.record_channel_change(self.client_mac, 6, 11, self.current_time + 60)
        
        result = self.miner.predict_channel_changes(self.client_mac)
        self.assertEqual(result['status'], 'insufficient_data')
    
    def test_predict_channel_changes_pattern(self):
        """Test predicting channel changes with discernible pattern"""
        # Add channel changes with a clear pattern: 1 -> 6 -> 11 -> 1 ...
        for i in range(10):
            old_channel = [1, 6, 11][i % 3]
            new_channel = [6, 11, 1][i % 3]
            self.miner.record_channel_change(self.client_mac, old_channel, new_channel, 
                                           self.current_time + i * 300)  # 5 minutes apart
        
        # Predict channel changes
        result = self.miner.predict_channel_changes(self.client_mac)
        
        # Verify prediction
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['pattern_detected'])
        self.assertIn('predicted_channel', result)
        self.assertIn('predicted_time', result)
        self.assertIn('confidence', result)
    
    def test_detect_periodic_behavior_no_pattern(self):
        """Test detecting periodic behavior with no clear pattern"""
        # Add activities at irregular intervals
        for i in range(15):
            # Non-periodic intervals
            self.miner.record_activity(self.client_mac, self.current_time + i * (100 + i * 10),
                                     'data', {})
        
        # Detect periodic behavior
        result = self.miner._detect_periodic_behavior(self.client_mac)
        
        # Should not detect periodicity
        self.assertFalse(result['detected'])
    
    def test_detect_periodic_behavior_with_pattern(self):
        """Test detecting periodic behavior with clear pattern"""
        # Add activities at regular intervals
        interval = 300  # 5 minutes
        for i in range(15):
            self.miner.record_activity(self.client_mac, self.current_time + i * interval,
                                     'beacon', {})
        
        # Detect periodic behavior
        result = self.miner._detect_periodic_behavior(self.client_mac)
        
        # Should detect periodicity
        self.assertTrue(result['detected'])
        self.assertAlmostEqual(result['interval_seconds'], interval, delta=10)
        self.assertGreater(result['confidence'], 0.5)
    
    def test_analyze_activity_sequences(self):
        """Test analyzing activity sequences"""
        # Add activities with a repeating sequence
        sequence = ['probe_request', 'association_request', 'data', 'deauthentication']
        
        # Repeat the sequence multiple times
        for j in range(3):
            for i, activity_type in enumerate(sequence):
                self.miner.record_activity(self.client_mac, 
                                         self.current_time + j * len(sequence) * 60 + i * 60,
                                         activity_type, {})
        
        # Add some random activities to make it more realistic
        self.miner.record_activity(self.client_mac, self.current_time + 1000, 'data', {})
        self.miner.record_activity(self.client_mac, self.current_time + 1100, 'beacon', {})
        
        # Analyze sequences
        result = self.miner._analyze_activity_sequences(self.client_mac)
        
        # Should detect sequences
        self.assertTrue(result['detected'])
        self.assertGreater(len(result['common_sequences']), 0)
        
        # Find our sequence (or part of it)
        found_match = False
        for seq_info in result['common_sequences']:
            if len(seq_info['sequence']) >= 2:
                # Check if at least a subsequence of our pattern is detected
                sequence_str = ','.join(seq_info['sequence'])
                original_str = ','.join(sequence)
                if sequence_str in original_str:
                    found_match = True
                    break
        
        self.assertTrue(found_match, "Pattern sequence not detected")
    
    def test_classify_behavior_type(self):
        """Test client behavior classification"""
        # Create test activities
        activities = []
        
        # Test highly active client
        for i in range(30):
            activities.append({
                'timestamp': self.current_time - 300 + i * 10,  # Recent, frequent activity
                'type': 'data',
                'category': 'traffic'
            })
        
        # Calculate density (30 activities in 5 minutes)
        density = 30 / 5
        
        # Classify behavior
        behavior = self.miner._classify_behavior_type(activities, density)
        self.assertEqual(behavior, 'highly_active')
        
        # Test currently active client
        activities = [{
            'timestamp': self.current_time - 60,  # Very recent
            'type': 'data',
            'category': 'traffic'
        }]
        
        # Calculate density
        density = 1 / 1
        
        # Classify behavior
        behavior = self.miner._classify_behavior_type(activities, density)
        self.assertEqual(behavior, 'currently_active')
        
        # Test disconnection prone client
        activities = [
            {'timestamp': self.current_time - 300, 'type': 'association_request', 'category': 'connection'},
            {'timestamp': self.current_time - 200, 'type': 'deauthentication', 'category': 'disconnection'},
            {'timestamp': self.current_time - 100, 'type': 'association_request', 'category': 'connection'},
            {'timestamp': self.current_time - 50, 'type': 'deauthentication', 'category': 'disconnection'}
        ]
        
        # Calculate density
        density = 4 / 5
        
        # Classify behavior
        behavior = self.miner._classify_behavior_type(activities, density)
        self.assertEqual(behavior, 'disconnection_prone')
    
    def test_get_most_active_hours(self):
        """Test finding most active hours"""
        # Set up hour patterns
        self.miner.hour_patterns[self.client_mac] = {
            9: 10,   # 10 activities at 9 AM
            12: 5,   # 5 activities at noon
            15: 20,  # 20 activities at 3 PM
            18: 5    # 5 activities at 6 PM
        }
        
        # Get most active hours
        active_hours = self.miner._get_most_active_hours(self.client_mac)
        
        # Verify results (should be sorted by count)
        self.assertEqual(len(active_hours), 3)  # Only hours with >=10% activity
        self.assertEqual(active_hours[0][0], 15)  # Most active hour
        self.assertEqual(active_hours[1][0], 9)   # Second most active
    
    def test_get_most_active_days(self):
        """Test finding most active days"""
        # Set up day patterns
        self.miner.day_patterns[self.client_mac] = {
            0: 10,  # 10 activities on Monday
            1: 5,   # 5 activities on Tuesday
            2: 20,  # 20 activities on Wednesday
            4: 5    # 5 activities on Friday
        }
        
        # Get most active days
        active_days = self.miner._get_most_active_days(self.client_mac)
        
        # Verify results (should be sorted by count)
        self.assertEqual(len(active_days), 4)
        self.assertEqual(active_days[0][0], 2)  # Most active day (Wednesday)
        self.assertEqual(active_days[1][0], 0)  # Second most active (Monday)
    
    def test_is_repeating_pattern(self):
        """Test repeating pattern detection"""
        # Simple repeating pattern
        sequence1 = [1, 2, 3, 1, 2, 3, 1, 2, 3]
        self.assertTrue(self.miner._is_repeating_pattern(sequence1, 3))
        
        # Not a repeating pattern
        sequence2 = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        self.assertFalse(self.miner._is_repeating_pattern(sequence2, 3))
        
        # Partial repeating pattern (not enough repetitions)
        sequence3 = [1, 2, 3, 1, 2, 4, 5, 6, 7]
        self.assertFalse(self.miner._is_repeating_pattern(sequence3, 3))
        
        # Too short for the pattern length
        sequence4 = [1, 2, 3, 4]
        self.assertFalse(self.miner._is_repeating_pattern(sequence4, 3))
    
    def test_get_client_patterns(self):
        """Test getting comprehensive client patterns"""
        # Add some activity data
        for i in range(10):
            self.miner.record_activity(self.client_mac, self.current_time + i * 60,
                                     ['data', 'probe_request'][i % 2], {})
        
        # Get client patterns
        patterns = self.miner.get_client_patterns(self.client_mac)
        
        # Verify response structure
        self.assertIn('behavioral_patterns', patterns)
        self.assertIn('timing_recommendation', patterns)
        
        # Verify behavioral patterns has all expected fields
        behavioral = patterns['behavioral_patterns']
        self.assertEqual(behavioral['status'], 'success')
        self.assertEqual(behavioral['client'], self.client_mac)
        self.assertIn('activity_count', behavioral)
        self.assertIn('behavior_type', behavioral)
        
        # Verify timing recommendation has all expected fields
        timing = patterns['timing_recommendation']
        self.assertIn('recommendation', timing)

if __name__ == '__main__':
    unittest.main()