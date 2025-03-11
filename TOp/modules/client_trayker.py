"""
Advanced Wireless Network Analysis Framework - Client Tracker Module

This module maintains state information for wireless clients, tracking their
connectivity, behavior, attack history, and physical characteristics to inform
adaptive analysis strategies.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Union, Any

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

class ClientTracker:
    """
    Tracks and manages wireless client state information to support analysis
    operations and adaptive strategy optimization.
    """
    
    def __init__(self, expiration_time: int = 3600, reconnect_threshold: int = 10):
        """
        Initialize the client tracker
        
        Args:
            expiration_time: Time in seconds after which a client is expired if not seen
            reconnect_threshold: Maximum number of reconnect events to track per client
        """
        self.expiration_time = expiration_time
        self.reconnect_threshold = reconnect_threshold
        
        # Client state tracking
        self.clients = {}
        
        # Attack history
        self.attack_history = defaultdict(list)
        
        # Performance metrics
        self.metrics = {
            'tracked_clients': 0,
            'active_clients': 0,
            'disconnected_clients': 0,
            'expired_clients': 0,
            'total_attacks': 0,
            'successful_attacks': 0
        }
    
    def update_client_seen(self, client_mac: str, signal_strength: int = None,
                          channel: int = None, ap_mac: str = None):
        """
        Update a client's last seen timestamp and information
        
        Args:
            client_mac: Client MAC address
            signal_strength: Signal strength in dBm (optional)
            channel: Wi-Fi channel (optional)
            ap_mac: Associated AP MAC address (optional)
        """
        current_time = time.time()
        
        # Initialize client state if not exists
        if client_mac not in self.clients:
            self.clients[client_mac] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'active': True,
                'disconnected': False,
                'disconnect_time': 0,
                'signal_strength': signal_strength,
                'channel': channel,
                'ap_mac': ap_mac,
                'attack_count': 0,
                'last_attack_time': 0,
                'reconnect_count': 0,
                'reconnect_times': [],
                'strategy': {}
            }
            self.metrics['tracked_clients'] += 1
            self.metrics['active_clients'] += 1
        else:
            # Update client state
            client = self.clients[client_mac]
            client['last_seen'] = current_time
            
            # Update active status if previously disconnected
            if client['disconnected']:
                # Client reconnected
                reconnect_time = current_time - client['disconnect_time']
                client['reconnect_times'].append(reconnect_time)
                
                # Cap reconnect times list
                if len(client['reconnect_times']) > self.reconnect_threshold:
                    client['reconnect_times'] = client['reconnect_times'][-self.reconnect_threshold:]
                
                client['reconnect_count'] += 1
                client['disconnected'] = False
                client['active'] = True
                
                # Update metrics
                self.metrics['disconnected_clients'] -= 1
                self.metrics['active_clients'] += 1
                
                logger.info(f"Client {client_mac} reconnected after {reconnect_time:.2f}s")
        
        # Update signal strength if provided
        if signal_strength is not None:
            self.clients[client_mac]['signal_strength'] = signal_strength
        
        # Update channel if provided
        if channel is not None:
            self.clients[client_mac]['channel'] = channel
        
        # Update AP if provided
        if ap_mac is not None:
            self.clients[client_mac]['ap_mac'] = ap_mac
    
    def set_disconnect_time(self, client_mac: str, timestamp: float = None):
        """
        Mark a client as disconnected
        
        Args:
            client_mac: Client MAC address
            timestamp: Disconnect timestamp (default: current time)
        """
        if timestamp is None:
            timestamp = time.time()
        
        if client_mac in self.clients:
            client = self.clients[client_mac]
            
            # Skip if already disconnected
            if client['disconnected']:
                return
            
            # Mark as disconnected
            client['disconnected'] = True
            client['active'] = False
            client['disconnect_time'] = timestamp
            
            # Update metrics
            self.metrics['disconnected_clients'] += 1
            self.metrics['active_clients'] -= 1
            
            # Count as successful attack if recently attacked
            attack_time = client.get('last_attack_time', 0)
            if timestamp - attack_time < 60:  # Within 60 seconds of attack
                self.metrics['successful_attacks'] += 1
                
                # Record attack success
                if self.attack_history[client_mac]:
                    self.attack_history[client_mac][-1]['success'] = True
            
            logger.debug(f"Client {client_mac} marked as disconnected")
    
    def update_attack_time(self, client_mac: str, attack_vector: str = None, 
                          strategy: Dict = None):
        """
        Update a client's last attack timestamp and information
        
        Args:
            client_mac: Client MAC address
            attack_vector: Attack vector used (optional)
            strategy: Attack strategy used (optional)
        """
        current_time = time.time()
        
        # Ensure client exists
        if client_mac not in self.clients:
            self.update_client_seen(client_mac)
        
        client = self.clients[client_mac]
        
        # Update attack information
        client['last_attack_time'] = current_time
        client['attack_count'] += 1
        
        # Update strategy if provided
        if strategy:
            client['strategy'] = strategy
        
        # Record attack details
        attack_record = {
            'timestamp': current_time,
            'vector': attack_vector,
            'strategy': strategy,
            'success': False  # Will be updated if disconnection is observed
        }
        self.attack_history[client_mac].append(attack_record)
        
        # Limit attack history size
        if len(self.attack_history[client_mac]) > 50:
            self.attack_history[client_mac] = self.attack_history[client_mac][-50:]
        
        # Update metrics
        self.metrics['total_attacks'] += 1
    
    def increment_attack_attempt(self, client_mac: str):
        """
        Increment the attack attempt counter for a client
        
        Args:
            client_mac: Client MAC address
        """
        if client_mac in self.clients:
            self.clients[client_mac]['attack_count'] += 1
    
    def add_reconnect_time(self, client_mac: str, reconnect_time: float):
        """
        Add a reconnect time for a client
        
        Args:
            client_mac: Client MAC address
            reconnect_time: Time taken to reconnect in seconds
        """
        if client_mac in self.clients:
            client = self.clients[client_mac]
            client['reconnect_times'].append(reconnect_time)
            
            # Cap reconnect times list
            if len(client['reconnect_times']) > self.reconnect_threshold:
                client['reconnect_times'] = client['reconnect_times'][-self.reconnect_threshold:]
    
    def update_client_strategy(self, client_mac: str, strategy: Dict):
        """
        Update the attack strategy for a client
        
        Args:
            client_mac: Client MAC address
            strategy: New strategy dictionary
        """
        if client_mac in self.clients:
            self.clients[client_mac]['strategy'] = strategy
    
    def clean_expired_clients(self):
        """
        Remove clients that haven't been seen for the expiration time
        """
        current_time = time.time()
        expired_macs = []
        
        for client_mac, client in self.clients.items():
            if current_time - client['last_seen'] > self.expiration_time:
                expired_macs.append(client_mac)
        
        # Remove expired clients
        for client_mac in expired_macs:
            del self.clients[client_mac]
            if client_mac in self.attack_history:
                del self.attack_history[client_mac]
            
            # Update metrics
            self.metrics['expired_clients'] += 1
            if self.clients[client_mac]['active']:
                self.metrics['active_clients'] -= 1
            else:
                self.metrics['disconnected_clients'] -= 1
            
            logger.debug(f"Expired client {client_mac} removed from tracking")
    
    def get_active_clients(self) -> List[str]:
        """
        Get a list of active client MAC addresses
        
        Returns:
            list: List of active client MAC addresses
        """
        return [
            client_mac for client_mac, client in self.clients.items()
            if client['active']
        ]
    
    def get_disconnected_clients(self) -> List[str]:
        """
        Get a list of disconnected client MAC addresses
        
        Returns:
            list: List of disconnected client MAC addresses
        """
        return [
            client_mac for client_mac, client in self.clients.items()
            if client['disconnected']
        ]
    
    def get_client_by_ap(self, ap_mac: str) -> List[str]:
        """
        Get a list of client MAC addresses associated with an AP
        
        Args:
            ap_mac: AP MAC address
            
        Returns:
            list: List of client MAC addresses
        """
        return [
            client_mac for client_mac, client in self.clients.items()
            if client['ap_mac'] == ap_mac
        ]
    
    def get_client_info(self, client_mac: str) -> Optional[Dict]:
        """
        Get detailed information for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Client information or None if not found
        """
        if client_mac not in self.clients:
            return None
        
        client = self.clients[client_mac]
        
        # Calculate additional metrics
        current_time = time.time()
        time_since_seen = current_time - client['last_seen']
        
        avg_reconnect_time = 0
        if client['reconnect_times']:
            avg_reconnect_time = sum(client['reconnect_times']) / len(client['reconnect_times'])
        
        # Calculate attack success rate
        attack_history = self.attack_history.get(client_mac, [])
        successful_attacks = sum(1 for attack in attack_history if attack.get('success', False))
        success_rate = successful_attacks / max(1, len(attack_history))
        
        # Create detailed client info
        return {
            'mac_address': client_mac,
            'first_seen': client['first_seen'],
            'last_seen': client['last_seen'],
            'time_since_seen': time_since_seen,
            'active': client['active'],
            'disconnected': client['disconnected'],
            'signal_strength': client['signal_strength'],
            'channel': client['channel'],
            'ap_mac': client['ap_mac'],
            'attack_count': client['attack_count'],
            'last_attack_time': client['last_attack_time'],
            'time_since_attack': current_time - client['last_attack_time'] if client['last_attack_time'] > 0 else None,
            'reconnect_count': client['reconnect_count'],
            'avg_reconnect_time': avg_reconnect_time,
            'current_strategy': client['strategy'],
            'attack_success_rate': success_rate,
            'attack_history_count': len(attack_history)
        }
    
    def get_client_attack_history(self, client_mac: str) -> List[Dict]:
        """
        Get attack history for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            list: List of attack records
        """
        return self.attack_history.get(client_mac, [])
    
    def get_last_seen(self, client_mac: str) -> float:
        """
        Get the last seen timestamp for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            float: Last seen timestamp or 0 if not found
        """
        if client_mac not in self.clients:
            return 0
        
        return self.clients[client_mac]['last_seen']
    
    def get_disconnect_time(self, client_mac: str) -> float:
        """
        Get the disconnect timestamp for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            float: Disconnect timestamp or 0 if not found/disconnected
        """
        if client_mac not in self.clients:
            return 0
        
        return self.clients[client_mac]['disconnect_time']
    
    def get_attack_count(self, client_mac: str) -> int:
        """
        Get the number of attacks attempted against a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            int: Attack count or 0 if not found
        """
        if client_mac not in self.clients:
            return 0
        
        return self.clients[client_mac]['attack_count']
    
    def get_last_attack_time(self, client_mac: str) -> float:
        """
        Get the last attack timestamp for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            float: Last attack timestamp or 0 if not found
        """
        if client_mac not in self.clients:
            return 0
        
        return self.clients[client_mac]['last_attack_time']
    
    def get_attempt_count(self, client_mac: str) -> int:
        """
        Get the number of attack attempts for a client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            int: Attack attempt count or 0 if not found
        """
        if client_mac not in self.clients:
            return 0
        
        return self.clients[client_mac]['attack_count']
    
    def get_metrics(self) -> Dict:
        """
        Get performance metrics
        
        Returns:
            dict: Performance metrics
        """
        # Calculate additional metrics
        if self.metrics['total_attacks'] > 0:
            self.metrics['success_rate'] = (
                self.metrics['successful_attacks'] / self.metrics['total_attacks']
            )
        else:
            self.metrics['success_rate'] = 0
        
        return self.metrics
    
    def export_client_data(self) -> Dict:
        """
        Export all client data for analysis or persistence
        
        Returns:
            dict: All client data
        """
        export_data = {
            'clients': self.clients,
            'attack_history': self.attack_history,
            'metrics': self.metrics,
            'export_time': time.time()
        }
        
        return export_data
    
    def import_client_data(self, data: Dict) -> bool:
        """
        Import client data from a previous export
        
        Args:
            data: Exported client data
            
        Returns:
            bool: True if import was successful
        """
        try:
            if 'clients' in data:
                self.clients = data['clients']
            
            if 'attack_history' in data:
                self.attack_history = data['attack_history']
            
            if 'metrics' in data:
                self.metrics = data['metrics']
            
            logger.info(f"Imported client data with {len(self.clients)} clients")
            return True
            
        except Exception as e:
            logger.error(f"Error importing client data: {e}")
            return False