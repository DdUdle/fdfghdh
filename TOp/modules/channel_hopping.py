"""
Wireless Network Analysis Framework - Channel Hopper Module

This module provides intelligent channel management capabilities for wireless interfaces,
optimizing channel distribution and dwell time based on network activity and analysis goals.
"""

import os
import time
import logging
import subprocess
import threading
from typing import Dict, List, Optional, Set, Tuple, Union, Any

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

class ChannelHopper:
    """
    Manages wireless interface channel switching for optimal monitoring and analysis.
    Supports both manual and adaptive channel hopping strategies with multi-interface
    coordination.
    """
    
    def __init__(self, interfaces: List[str], preferred_channels: List[int] = None):
        """
        Initialize the channel hopper
        
        Args:
            interfaces: List of wireless interfaces to manage
            preferred_channels: List of preferred channels to use (default: None)
        """
        self.interfaces = interfaces
        self.preferred_channels = preferred_channels or [1, 6, 11]  # Default to common 2.4GHz channels
        
        # Track current channel for each interface
        self.current_channels = {interface: None for interface in interfaces}
        
        # Thread control
        self.hopping_active = False
        self.hopping_thread = None
        self.thread_lock = threading.Lock()
        
        # Channel metrics for adaptive hopping
        self.channel_metrics = {}  # Channel -> performance metric
        self.channel_activity = {}  # Channel -> activity count
        self.last_hop_time = 0
        
        # Configure hop interval (in seconds)
        self.hop_interval = 0.3
        self.adaptive_mode = False
        
        logger.info(f"Channel hopper initialized with interfaces: {', '.join(interfaces)}")
    
    def set_channel(self, interface: str, channel: int) -> bool:
        """
        Set a specific interface to a given channel
        
        Args:
            interface: Wireless interface name
            channel: Channel number to set
            
        Returns:
            bool: True if successful, False otherwise
        """
        if interface not in self.interfaces:
            logger.error(f"Interface {interface} not found")
            return False
        
        try:
            # Using iw command to set channel
            command = ["iw", "dev", interface, "set", "channel", str(channel)]
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to set channel {channel} on {interface}: {result.stderr}")
                return False
            
            # Update current channel tracking
            self.current_channels[interface] = channel
            logger.debug(f"Set {interface} to channel {channel}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting channel on {interface}: {e}")
            return False
    
    def get_current_channel(self, interface: str) -> int:
        """
        Get the current channel for a specific interface
        
        Args:
            interface: Wireless interface name
            
        Returns:
            int: Current channel or None if unknown/error
        """
        if interface not in self.interfaces:
            logger.error(f"Interface {interface} not found")
            return None
        
        # Check if we already know the channel
        if self.current_channels[interface] is not None:
            return self.current_channels[interface]
        
        try:
            # Get current channel using iw command
            command = ["iw", "dev", interface, "info"]
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to get info for {interface}: {result.stderr}")
                return None
            
            # Parse output to find channel
            for line in result.stdout.splitlines():
                if "channel" in line:
                    parts = line.strip().split()
                    for i, part in enumerate(parts):
                        if part == "channel":
                            # Extract channel number
                            try:
                                channel = int(parts[i+1].split('(')[0])
                                self.current_channels[interface] = channel
                                return channel
                            except (IndexError, ValueError):
                                pass
            
            logger.warning(f"Could not determine current channel for {interface}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting current channel for {interface}: {e}")
            return None
    
    def hop_between_channels(self, channels: List[int] = None) -> bool:
        """
        Hop between specified channels across available interfaces
        
        Args:
            channels: List of channels to hop between (default: preferred_channels)
            
        Returns:
            bool: True if hopping started successfully, False otherwise
        """
        if not self.interfaces:
            logger.error("No interfaces available for channel hopping")
            return False
        
        hop_channels = channels or self.preferred_channels
        if not hop_channels:
            logger.error("No channels specified for hopping")
            return False
        
        # Distribute channels optimally across interfaces
        try:
            if len(self.interfaces) == 1:
                # Single interface - just set to first channel
                interface = self.interfaces[0]
                return self.set_channel(interface, hop_channels[0])
            else:
                # Multiple interfaces - distribute channels
                channels_per_interface = len(hop_channels) // len(self.interfaces)
                remainder = len(hop_channels) % len(self.interfaces)
                
                start_idx = 0
                for i, interface in enumerate(self.interfaces):
                    # Calculate channels for this interface
                    count = channels_per_interface + (1 if i < remainder else 0)
                    end_idx = start_idx + count
                    interface_channels = hop_channels[start_idx:end_idx]
                    start_idx = end_idx
                    
                    if interface_channels:
                        # Set interface to first assigned channel
                        self.set_channel(interface, interface_channels[0])
            
            return True
            
        except Exception as e:
            logger.error(f"Error in channel distribution: {e}")
            return False
    
    def start_adaptive_hopping(self, performance_metrics: Dict[int, float] = None) -> bool:
        """
        Start adaptive channel hopping based on performance metrics
        
        Args:
            performance_metrics: Dictionary of channel -> performance metric
                Higher values indicate channels to spend more time on
                
        Returns:
            bool: True if started successfully, False otherwise
        """
        if not self.interfaces:
            logger.error("No interfaces available for adaptive hopping")
            return False
        
        with self.thread_lock:
            # Stop any existing hopping thread
            if self.hopping_active:
                self.stop_hopping()
            
            self.hopping_active = True
            self.adaptive_mode = True
            
            # Initialize or update metrics
            if performance_metrics:
                self.channel_metrics = performance_metrics.copy()
            
            # Start the hopping thread
            self.hopping_thread = threading.Thread(
                target=self._adaptive_hopping_thread,
                daemon=True
            )
            self.hopping_thread.start()
            
            logger.info("Started adaptive channel hopping")
            return True
    
    def _adaptive_hopping_thread(self):
        """Thread function for adaptive channel hopping"""
        channels = list(self.preferred_channels)
        
        # Add any channels from metrics not in preferred
        for channel in self.channel_metrics:
            if channel not in channels:
                channels.append(channel)
        
        interface_idx = 0
        channel_idx = 0
        
        try:
            while self.hopping_active:
                # Get current interface and channel
                interface = self.interfaces[interface_idx]
                channel = channels[channel_idx]
                
                # Calculate dwell time based on metrics
                dwell_time = self.hop_interval
                if channel in self.channel_metrics:
                    # Scale dwell time by performance metric (normalized)
                    metric = self.channel_metrics[channel]
                    max_metric = max(self.channel_metrics.values()) if self.channel_metrics else 1.0
                    dwell_factor = max(0.5, min(3.0, metric / max(0.1, max_metric)))
                    dwell_time *= dwell_factor
                
                # Set the channel
                self.set_channel(interface, channel)
                
                # Update last hop time
                self.last_hop_time = time.time()
                
                # Sleep for the calculated dwell time
                time.sleep(dwell_time)
                
                # Move to next interface/channel
                interface_idx = (interface_idx + 1) % len(self.interfaces)
                if interface_idx == 0:
                    channel_idx = (channel_idx + 1) % len(channels)
                
        except Exception as e:
            logger.error(f"Error in adaptive hopping thread: {e}")
            self.hopping_active = False
    
    def stop_hopping(self) -> bool:
        """
        Stop the channel hopping process
        
        Returns:
            bool: True if stopped successfully, False otherwise
        """
        with self.thread_lock:
            self.hopping_active = False
            
            if self.hopping_thread and self.hopping_thread.is_alive():
                self.hopping_thread.join(timeout=1.0)
                self.hopping_thread = None
            
            logger.info("Stopped channel hopping")
            return True
    
    def update_channel_activity(self, channel: int, activity_count: int):
        """
        Update the activity count for a specific channel
        
        Args:
            channel: Channel number
            activity_count: Number of activities observed
        """
        self.channel_activity[channel] = self.channel_activity.get(channel, 0) + activity_count
        
        # Use activity to influence adaptive hopping metrics
        if channel in self.channel_metrics:
            # Increase metric based on activity
            self.channel_metrics[channel] = (
                self.channel_metrics[channel] * 0.7 + 
                activity_count * 0.3
            )
        else:
            self.channel_metrics[channel] = float(activity_count)
    
    def get_optimal_channel_allocation(self) -> Dict[str, List[int]]:
        """
        Get optimal channel allocation for multiple interfaces
        
        Returns:
            dict: Interface name -> list of assigned channels
        """
        if not self.interfaces:
            return {}
            
        # Sort channels by activity/metrics
        sorted_channels = sorted(
            self.channel_metrics.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        channel_list = [c[0] for c in sorted_channels]
        
        # If we have metrics but not enough channels, add preferred ones
        for channel in self.preferred_channels:
            if channel not in channel_list:
                channel_list.append(channel)
        
        # Fallback to preferred channels if no metrics
        if not channel_list:
            channel_list = self.preferred_channels.copy()
        
        # Allocate channels to interfaces
        allocation = {}
        for i, interface in enumerate(self.interfaces):
            # Distribute channels round-robin
            interface_channels = [
                channel_list[j] 
                for j in range(i, len(channel_list), len(self.interfaces))
            ]
            allocation[interface] = interface_channels
        
        return allocation