"""
Advanced Wireless Network Analysis Framework - Temporal Pattern Miner

This module analyzes temporal patterns in wireless network behavior to identify
optimal timing for analysis operations, detect behavioral signatures, and
predict device actions.
"""

import logging
import math
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Union, Any

# Try to import numpy for statistical analysis
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

class TemporalPatternMiner:
    """
    Analyzes temporal patterns in device behavior to optimize timing
    and predict future behaviors.
    """
    
    def __init__(self, max_history: int = 500, max_pattern_length: int = 10):
        """
        Initialize the temporal pattern miner
        
        Args:
            max_history: Maximum number of events to keep per client
            max_pattern_length: Maximum pattern length to detect
        """
        self.max_history = max_history
        self.max_pattern_length = max_pattern_length
        
        # Data structures for pattern analysis
        self.client_activity = defaultdict(list)       # Client MAC -> list of activity records
        self.activity_types = defaultdict(set)         # Client MAC -> set of observed activity types
        self.time_intervals = defaultdict(list)        # Client MAC -> list of time intervals between activities
        self.reconnect_patterns = defaultdict(list)    # Client MAC -> list of reconnect time records
        self.channel_patterns = defaultdict(list)      # BSSID/Client MAC -> list of channel change records
        self.day_patterns = defaultdict(lambda: defaultdict(int))  # Client MAC -> day of week -> count
        self.hour_patterns = defaultdict(lambda: defaultdict(int))  # Client MAC -> hour of day -> count
        
        # Pattern detection thresholds
        self.min_pattern_occurrences = 2      # Minimum occurrences to recognize a pattern
        self.max_interval_variance = 0.25     # Maximum allowed variance in time intervals (as percentage)
        
        # Activity type categorization
        self.activity_categories = {
            'association_request': 'connection',
            'association_response': 'connection',
            'probe_request': 'discovery',
            'probe_response': 'discovery',
            'authentication': 'connection',
            'deauthentication': 'disconnection',
            'disassociation': 'disconnection',
            'beacon': 'maintenance',
            'data': 'traffic',
            'control': 'maintenance',
            'disconnected': 'disconnection',
            'reconnected': 'connection'
        }
    
    def record_activity(self, client_mac: str, timestamp: float, activity_type: str, 
                       metadata: Optional[Dict] = None):
        """
        Record client activity for pattern analysis
        
        Args:
            client_mac: Client MAC address
            timestamp: Unix timestamp of the activity
            activity_type: Type of activity (e.g., 'probe_request', 'data')
            metadata: Additional metadata about the activity
        """
        if not metadata:
            metadata = {}
            
        # Categorize activity
        category = self.activity_categories.get(activity_type, 'other')
        
        # Create activity record
        activity = {
            'timestamp': timestamp,
            'type': activity_type,
            'category': category,
            'metadata': metadata
        }
        
        # Add to activity history
        client_activities = self.client_activity[client_mac]
        client_activities.append(activity)
        
        # Keep history within limits
        if len(client_activities) > self.max_history:
            client_activities = client_activities[-self.max_history:]
            self.client_activity[client_mac] = client_activities
        
        # Record activity type
        self.activity_types[client_mac].add(activity_type)
        
        # Record time interval from previous activity of same type
        for prev_activity in reversed(client_activities[:-1]):
            if prev_activity['type'] == activity_type:
                interval = timestamp - prev_activity['timestamp']
                if 0 < interval < 3600:  # Reasonable interval (1 hour max)
                    self.time_intervals[f"{client_mac}:{activity_type}"].append(interval)
                break
        
        # Record reconnect specifically
        if activity_type == 'reconnected' and 'time' in metadata:
            reconnect_time = metadata['time']
            self.reconnect_patterns[client_mac].append({
                'timestamp': timestamp,
                'reconnect_time': reconnect_time
            })
            
        # Update time-of-day patterns
        dt = datetime.fromtimestamp(timestamp)
        self.hour_patterns[client_mac][dt.hour] += 1
        self.day_patterns[client_mac][dt.weekday()] += 1
    
    def record_channel_change(self, mac_address: str, old_channel: Union[str, int], 
                            new_channel: Union[str, int], timestamp: float):
        """
        Record channel change for pattern analysis
        
        Args:
            mac_address: AP or client MAC address
            old_channel: Previous channel
            new_channel: New channel
            timestamp: Unix timestamp of the change
        """
        # Ensure channels are integers
        if isinstance(old_channel, str):
            try:
                old_channel = int(old_channel)
            except ValueError:
                logger.warning(f"Invalid old channel value: {old_channel}")
                return
                
        if isinstance(new_channel, str):
            try:
                new_channel = int(new_channel)
            except ValueError:
                logger.warning(f"Invalid new channel value: {new_channel}")
                return
        
        # Record channel change
        self.channel_patterns[mac_address].append({
            'timestamp': timestamp,
            'old_channel': old_channel,
            'new_channel': new_channel
        })
        
        # Keep history within limits
        if len(self.channel_patterns[mac_address]) > self.max_history:
            self.channel_patterns[mac_address] = self.channel_patterns[mac_address][-self.max_history:]
    
    def analyze_patterns(self, client_mac: str) -> Dict:
        """
        Analyze temporal patterns for a specific client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Analysis results
        """
        if client_mac not in self.client_activity or len(self.client_activity[client_mac]) < 5:
            return {'status': 'insufficient_data'}
        
        try:
            activities = self.client_activity[client_mac]
            
            # Calculate activity density (activities per minute)
            if len(activities) >= 2:
                time_span = activities[-1]['timestamp'] - activities[0]['timestamp']
                if time_span > 0:
                    density = len(activities) / (time_span / 60)
                else:
                    density = 0
            else:
                density = 0
            
            # Get most active periods
            active_hours = self._get_most_active_hours(client_mac)
            active_days = self._get_most_active_days(client_mac)
            
            # Calculate median reconnect time if available
            median_reconnect = None
            if client_mac in self.reconnect_patterns and self.reconnect_patterns[client_mac]:
                reconnect_times = [entry['reconnect_time'] for entry in self.reconnect_patterns[client_mac]]
                if NUMPY_AVAILABLE:
                    median_reconnect = float(np.median(reconnect_times))
                else:
                    # Manual median calculation
                    sorted_times = sorted(reconnect_times)
                    mid = len(sorted_times) // 2
                    if len(sorted_times) % 2 == 0:
                        median_reconnect = (sorted_times[mid-1] + sorted_times[mid]) / 2
                    else:
                        median_reconnect = sorted_times[mid]
            
            # Detect periodic behaviors
            periodic_patterns = self._detect_periodic_behavior(client_mac)
            
            # Analyze activity sequences
            activity_sequences = self._analyze_activity_sequences(client_mac)
            
            # Determine client behavior type
            behavior_type = self._classify_behavior_type(activities, density)
            
            # Calculate activity type distribution
            activity_distribution = {}
            for activity in activities:
                activity_type = activity['type']
                activity_distribution[activity_type] = activity_distribution.get(activity_type, 0) + 1
            
            # Normalize distribution
            if activities:
                activity_distribution = {k: v / len(activities) for k, v in activity_distribution.items()}
            
            # Generate comprehensive analysis result
            return {
                'status': 'success',
                'client': client_mac,
                'activity_count': len(activities),
                'activity_density': density,
                'active_hours': active_hours,
                'active_days': active_days,
                'median_reconnect_time': median_reconnect,
                'periodic_behavior': periodic_patterns,
                'activity_sequences': activity_sequences,
                'behavior_type': behavior_type,
                'activity_distribution': activity_distribution,
                'data_quality': 'high' if len(activities) > 20 else 'medium' if len(activities) > 10 else 'low'
            }
        
        except Exception as e:
            logger.error(f"Error analyzing patterns for {client_mac}: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_optimal_attack_timing(self, client_mac: str) -> Dict:
        """
        Determine optimal timing for operations based on client patterns
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Timing recommendation
        """
        if client_mac not in self.client_activity or len(self.client_activity[client_mac]) < 5:
            return {'recommendation': 'immediate'}
        
        try:
            activities = self.client_activity[client_mac]
            
            # Default is immediate action
            timing = {'recommendation': 'immediate', 'confidence': 1.0}
            
            # Check time since last activity
            current_time = time.time()
            last_activity = activities[-1]
            time_since_last = current_time - last_activity['timestamp']
            
            # If client was recently disconnected, suggest delay
            if last_activity['category'] == 'disconnection' and time_since_last < 10:
                timing = {
                    'recommendation': 'delayed',
                    'delay': 15.0,  # Standard delay after disconnection
                    'reason': 'recent_disconnection',
                    'confidence': 0.8,
                    'expected_success_boost': 0.2
                }
                
            # Check for periodic behavior
            periodic_patterns = self._detect_periodic_behavior(client_mac)
            if periodic_patterns.get('detected', False):
                interval = periodic_patterns.get('interval_seconds', 0)
                next_expected = last_activity['timestamp'] + interval
                
                # If next expected activity is in the future, delay until then
                if next_expected > current_time:
                    delay = next_expected - current_time
                    if delay < 60:  # Reasonable delay (< 1 minute)
                        timing = {
                            'recommendation': 'delayed',
                            'delay': delay,
                            'reason': 'pattern_alignment',
                            'confidence': periodic_patterns.get('confidence', 0.5),
                            'expected_success_boost': 0.3
                        }
            
            # If client has reconnection pattern, time attacks to break pattern
            if client_mac in self.reconnect_patterns and len(self.reconnect_patterns[client_mac]) >= 2:
                # Calculate median reconnect time
                reconnect_times = [entry['reconnect_time'] for entry in self.reconnect_patterns[client_mac]]
                if NUMPY_AVAILABLE:
                    median_time = float(np.median(reconnect_times))
                else:
                    # Manual median calculation
                    sorted_times = sorted(reconnect_times)
                    mid = len(sorted_times) // 2
                    if len(sorted_times) % 2 == 0:
                        median_time = (sorted_times[mid-1] + sorted_times[mid]) / 2
                    else:
                        median_time = sorted_times[mid]
                
                if median_time < 20:  # Quick reconnects
                    # Time attack just after expected reconnect
                    timing = {
                        'recommendation': 'delayed',
                        'delay': median_time + 0.5,
                        'reason': 'reconnect_interception',
                        'confidence': 0.75,
                        'expected_success_boost': 0.25
                    }
            
            # Check for high-activity periods that might be more vulnerable
            if self.hour_patterns[client_mac]:
                # Get current hour
                current_hour = datetime.now().hour
                
                # Get most active hours
                most_active = self._get_most_active_hours(client_mac)
                
                if most_active:
                    most_active_hours = [h[0] for h in most_active]
                    
                    if current_hour in most_active_hours:
                        # Current hour is a high-activity period
                        timing = {
                            'recommendation': 'immediate',
                            'reason': 'high_activity_period',
                            'confidence': 0.9,
                            'expected_success_boost': 0.2
                        }
            
            return timing
            
        except Exception as e:
            logger.error(f"Error determining optimal timing for {client_mac}: {e}")
            return {'recommendation': 'immediate'}
    
    def predict_channel_changes(self, mac_address: str) -> Dict:
        """
        Predict future channel changes based on observed patterns
        
        Args:
            mac_address: AP or client MAC address
            
        Returns:
            dict: Prediction results
        """
        if (mac_address not in self.channel_patterns or 
            len(self.channel_patterns[mac_address]) < 3):
            return {'status': 'insufficient_data'}
        
        try:
            channel_history = self.channel_patterns[mac_address]
            
            # Extract channels and intervals
            channels = [record['new_channel'] for record in channel_history]
            intervals = []
            for i in range(1, len(channel_history)):
                interval = channel_history[i]['timestamp'] - channel_history[i-1]['timestamp']
                intervals.append(interval)
            
            # Check for repeating channel pattern
            pattern_detected = False
            predicted_channel = None
            predicted_time = 0
            confidence = 0.0
            
            # Look for patterns of different lengths
            for pattern_length in range(1, min(self.max_pattern_length, len(channels) // 2)):
                if self._is_repeating_pattern(channels, pattern_length):
                    pattern_detected = True
                    
                    # Predict next channel in sequence
                    next_index = len(channels) % pattern_length
                    predicted_channel = channels[next_index]
                    
                    # Calculate average interval and predict time
                    if intervals:
                        # Use recent intervals for prediction
                        recent_intervals = intervals[-pattern_length:] if len(intervals) >= pattern_length else intervals
                        avg_interval = sum(recent_intervals) / len(recent_intervals)
                        predicted_time = channel_history[-1]['timestamp'] + avg_interval
                        
                        # Calculate confidence based on interval consistency
                        if NUMPY_AVAILABLE and len(recent_intervals) > 1:
                            std_dev = np.std(recent_intervals)
                            if avg_interval > 0:
                                # Lower variation = higher confidence
                                variation = std_dev / avg_interval
                                confidence = max(0.5, 1.0 - min(1.0, variation))
                            else:
                                confidence = 0.5
                        else:
                            confidence = 0.7  # Default confidence for detected pattern
                    
                    break
            
            if pattern_detected:
                return {
                    'status': 'success',
                    'pattern_detected': True,
                    'predicted_channel': predicted_channel,
                    'predicted_time': predicted_time,
                    'time_until_change': predicted_time - time.time(),
                    'confidence': confidence,
                    'pattern_length': pattern_length
                }
            else:
                return {
                    'status': 'success',
                    'pattern_detected': False
                }
                
        except Exception as e:
            logger.error(f"Error predicting channel changes for {mac_address}: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _detect_periodic_behavior(self, client_mac: str) -> Dict:
        """
        Detect if activities follow a periodic pattern
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Periodic behavior information if detected
        """
        activities = self.client_activity.get(client_mac, [])
        if len(activities) < 10:
            return {'detected': False}
        
        try:
            # Extract timestamps
            timestamps = [activity['timestamp'] for activity in activities]
            
            # Calculate intervals between consecutive activities
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            # Check for consistent intervals (within variance threshold)
            if len(intervals) >= 5:
                # Group similar intervals
                interval_groups = defaultdict(int)
                for interval in intervals:
                    # Round to nearest 5 seconds for grouping
                    rounded = round(interval / 5) * 5
                    interval_groups[rounded] += 1
                
                # Find most common interval
                if interval_groups:
                    most_common = max(interval_groups.items(), key=lambda x: x[1])
                    interval_value, count = most_common
                    
                    # Check if frequent enough to be considered periodic
                    if count >= len(intervals) * 0.3:  # At least 30% of intervals
                        # Calculate confidence based on consistency
                        confidence = count / len(intervals)
                        
                        return {
                            'detected': True,
                            'interval_seconds': interval_value,
                            'confidence': confidence,
                            'occurrence_count': count,
                            'total_intervals': len(intervals)
                        }
            
            # Check for activity type specific patterns
            for activity_type in self.activity_types.get(client_mac, set()):
                # Get intervals for this activity type
                type_intervals = self.time_intervals.get(f"{client_mac}:{activity_type}", [])
                
                if len(type_intervals) >= 3:
                    # Group similar intervals
                    interval_groups = defaultdict(int)
                    for interval in type_intervals:
                        # Round to nearest 5 seconds
                        rounded = round(interval / 5) * 5
                        interval_groups[rounded] += 1
                    
                    # Find most common interval
                    if interval_groups:
                        most_common = max(interval_groups.items(), key=lambda x: x[1])
                        interval_value, count = most_common
                        
                        # Check if frequent enough
                        if count >= len(type_intervals) * 0.4:  # 40% for type-specific
                            confidence = count / len(type_intervals)
                            
                            return {
                                'detected': True,
                                'activity_type': activity_type,
                                'interval_seconds': interval_value,
                                'confidence': confidence,
                                'occurrence_count': count,
                                'total_intervals': len(type_intervals)
                            }
            
            return {'detected': False}
            
        except Exception as e:
            logger.error(f"Error detecting periodic behavior: {e}")
            return {'detected': False}
    
    def _analyze_activity_sequences(self, client_mac: str) -> Dict:
        """
        Analyze sequences of activities to detect patterns
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Sequence analysis results
        """
        activities = self.client_activity.get(client_mac, [])
        if len(activities) < 5:
            return {'detected': False}
        
        try:
            # Extract sequence of activity types
            activity_sequence = [activity['type'] for activity in activities]
            
            # Look for common sub-sequences
            common_sequences = []
            
            # Check sequences of different lengths
            for seq_length in range(2, min(5, len(activity_sequence) // 2)):
                # Sliding window to extract all sub-sequences
                sub_sequences = defaultdict(int)
                for i in range(len(activity_sequence) - seq_length + 1):
                    seq = tuple(activity_sequence[i:i+seq_length])
                    sub_sequences[seq] += 1
                
                # Find common sub-sequences (occurring more than once)
                for seq, count in sub_sequences.items():
                    if count >= 2:
                        common_sequences.append({
                            'sequence': seq,
                            'length': len(seq),
                            'occurrences': count
                        })
            
            # Sort by occurrences (most frequent first)
            common_sequences.sort(key=lambda x: x['occurrences'], reverse=True)
            
            if common_sequences:
                return {
                    'detected': True,
                    'common_sequences': common_sequences[:5]  # Top 5 sequences
                }
            else:
                return {'detected': False}
                
        except Exception as e:
            logger.error(f"Error analyzing activity sequences: {e}")
            return {'detected': False}
    
    def _classify_behavior_type(self, activities: List[Dict], density: float) -> str:
        """
        Classify client behavior type based on activity patterns
        
        Args:
            activities: List of activity records
            density: Activity density (activities per minute)
            
        Returns:
            str: Behavior classification
        """
        if not activities:
            return 'unknown'
        
        try:
            # Analyze recency
            current_time = time.time()
            last_activity_time = activities[-1]['timestamp']
            time_since_last = current_time - last_activity_time
            
            # Count activity categories
            categories = defaultdict(int)
            for activity in activities:
                categories[activity['category']] += 1
            
            # Calculate category percentages
            total_activities = len(activities)
            category_percentages = {
                category: count / total_activities
                for category, count in categories.items()
            }
            
            # Determine behavior type
            if density > 10:  # Very active
                return 'highly_active'
            elif density > 3:  # Moderately active
                return 'active'
            elif time_since_last < 300 and categories.get('traffic', 0) > 0:  # Recent traffic
                return 'currently_active'
            elif category_percentages.get('connection', 0) > category_percentages.get('disconnection', 0) * 2:
                return 'connection_dominant'
            elif category_percentages.get('disconnection', 0) > category_percentages.get('connection', 0):
                return 'disconnection_prone'
            elif category_percentages.get('discovery', 0) > 0.5:
                return 'discovery_heavy'
            else:
                return 'irregular'
                
        except Exception as e:
            logger.error(f"Error classifying behavior type: {e}")
            return 'unknown'
    
    def _get_most_active_hours(self, client_mac: str) -> List[Tuple[int, float]]:
        """
        Get most active hours for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            list: List of (hour, activity_percentage) tuples
        """
        hour_counts = self.hour_patterns.get(client_mac, {})
        if not hour_counts:
            return []
        
        try:
            # Calculate total counts
            total_count = sum(hour_counts.values())
            if total_count == 0:
                return []
            
            # Calculate percentages
            hour_percentages = [
                (hour, count / total_count)
                for hour, count in hour_counts.items()
            ]
            
            # Sort by percentage (descending)
            hour_percentages.sort(key=lambda x: x[1], reverse=True)
            
            # Return top hours (those with at least 10% activity)
            return [hp for hp in hour_percentages if hp[1] >= 0.1]
            
        except Exception as e:
            logger.error(f"Error getting active hours: {e}")
            return []
    
    def _get_most_active_days(self, client_mac: str) -> List[Tuple[int, float]]:
        """
        Get most active days for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            list: List of (day, activity_percentage) tuples
        """
        day_counts = self.day_patterns.get(client_mac, {})
        if not day_counts:
            return []
        
        try:
            # Calculate total counts
            total_count = sum(day_counts.values())
            if total_count == 0:
                return []
            
            # Calculate percentages
            day_percentages = [
                (day, count / total_count)
                for day, count in day_counts.items()
            ]
            
            # Sort by percentage (descending)
            day_percentages.sort(key=lambda x: x[1], reverse=True)
            
            # Return all days with their percentages
            return day_percentages
            
        except Exception as e:
            logger.error(f"Error getting active days: {e}")
            return []
    
    def _is_repeating_pattern(self, sequence: List, pattern_length: int) -> bool:
        """
        Check if a sequence contains a repeating pattern of given length
        
        Args:
            sequence: Sequence to check
            pattern_length: Length of pattern to detect
            
        Returns:
            bool: True if repeating pattern detected
        """
        if len(sequence) < pattern_length * 2:
            return False
        
        # Check if the pattern repeats at least once
        pattern = sequence[:pattern_length]
        next_segment = sequence[pattern_length:pattern_length*2]
        
        return pattern == next_segment
    
    def get_client_patterns(self, client_mac: str) -> Dict:
        """
        Get comprehensive pattern information for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Pattern information
        """
        # Perform full pattern analysis
        patterns = self.analyze_patterns(client_mac)
        
        # Add optimal timing information
        timing = self.get_optimal_attack_timing(client_mac)
        
        # Combine results
        return {
            'behavioral_patterns': patterns,
            'timing_recommendation': timing
        }