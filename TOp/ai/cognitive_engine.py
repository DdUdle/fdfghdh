"""
Advanced Wireless Network Analysis Framework - Cognitive Engine

This module implements a sophisticated reinforcement learning system with neural
network-backed decision making for adaptive strategy optimization and 
client behavior modeling.
"""

import hashlib
import json
import logging
import math
import os
import random
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Union, Any

# Try to import ML libraries - graceful fallback if unavailable
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from ..utils.logging import setup_logger
from ..core.constants import (
    ATTACK_VECTORS, DEAUTH_REASON_CODES, DEVICE_CATEGORIES
)

# Configure logger
logger = setup_logger(__name__)

# Define neural network architecture if PyTorch is available
if TORCH_AVAILABLE:
    class DeepQNetwork(nn.Module):
        """Neural network for Q-value prediction"""
        
        def __init__(self, input_dim: int, output_dim: int, hidden_dims: List[int] = [128, 64]):
            super(DeepQNetwork, self).__init__()
            
            # Build network layers
            layers = []
            prev_dim = input_dim
            
            for dim in hidden_dims:
                layers.append(nn.Linear(prev_dim, dim))
                layers.append(nn.ReLU())
                prev_dim = dim
            
            layers.append(nn.Linear(prev_dim, output_dim))
            
            self.network = nn.Sequential(*layers)
        
        def forward(self, x):
            """Forward pass through the network"""
            return self.network(x)
    
    class SequenceModel(nn.Module):
        """Sequence model for temporal pattern analysis"""
        
        def __init__(self, input_dim: int, hidden_dim: int = 64, num_layers: int = 2, dropout: float = 0.2):
            super(SequenceModel, self).__init__()
            
            self.lstm = nn.LSTM(
                input_size=input_dim,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0
            )
            
            self.output = nn.Linear(hidden_dim, 1)  # Predict success probability
        
        def forward(self, x, hidden=None):
            """Forward pass through the network"""
            # x shape: [batch_size, seq_len, input_dim]
            lstm_out, hidden = self.lstm(x, hidden)
            
            # Use only the last output for prediction
            output = self.output(lstm_out[:, -1, :])
            return output, hidden

class CognitiveEngine:
    """
    Advanced AI-driven cognitive engine for learning and optimizing attack strategies.
    Uses reinforcement learning with optional neural networks for optimal decision making.
    """
    
    def __init__(self, learning_rate: float = 0.001, discount_factor: float = 0.95,
                exploration_rate: float = 0.2, pattern_miner = None, save_dir: str = None):
        """
        Initialize the cognitive engine
        
        Args:
            learning_rate: Learning rate for model training
            discount_factor: Discount factor for future rewards
            exploration_rate: Initial exploration rate
            pattern_miner: Optional temporal pattern miner instance
            save_dir: Directory to save models and data
        """
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.exploration_rate = exploration_rate
        self.pattern_miner = pattern_miner
        self.save_dir = save_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'models')
        
        # Create save directory if it doesn't exist
        if self.save_dir and not os.path.exists(self.save_dir):
            try:
                os.makedirs(self.save_dir)
            except Exception as e:
                logger.warning(f"Could not create save directory: {e}")
        
        # Determine device for PyTorch
        self.device = torch.device("cuda" if TORCH_AVAILABLE and torch.cuda.is_available() else "cpu") if TORCH_AVAILABLE else None
        
        # Initialize state tracking
        self.client_states = {}
        self.action_history = defaultdict(list)  # Client MAC -> list of (action, reward) tuples
        self.sequence_data = defaultdict(list)   # Client MAC -> list of (state, action, reward) tuples
        
        # Feature definitions
        self.feature_names = [
            'device_category',      # Encoded device type
            'signal_strength',      # Signal strength in dBm
            'protection_level',     # 0=None, 1=PMF, 2=PMF_Required
            'reconnect_count',      # Number of times client has reconnected
            'attack_count',         # Number of attacks attempted
            'success_rate',         # Success rate of previous attacks
            'time_since_last_seen', # Time since client was last seen (normalized)
            'client_activity',      # Client activity level (normalized)
            'time_of_day',          # Hour of day (normalized)
            'channel'               # WiFi channel (normalized)
        ]
        
        # Action space - first initialize with key vectors
        self.action_space = self._initialize_action_space()
        
        # Action performance tracking
        self.action_stats = {i: {
            'success_count': 0,
            'attempt_count': 0,
            'total_reward': 0.0,
            'avg_reward': 0.5,  # Initialize optimistically
            'success_rate': 0.0,
            'last_used': 0
        } for i in range(len(self.action_space))}
        
        # Vector type success tracking
        self.vector_stats = {vector: {
            'success_count': 0,
            'attempt_count': 0,
            'success_rate': 0.0
        } for vector in ATTACK_VECTORS.keys()}
        
        # Strategy preferences by device category
        self.category_preferences = {}
        
        # Attack preference - determines reward calculation weights
        self.attack_preference = 'balanced'  # Options: 'balanced', 'stealth', 'speed', 'efficiency'
        
        # Initialize neural networks if available
        self.policy_network = None
        self.target_network = None
        self.sequence_model = None
        self.optimizer = None
        self.sequence_optimizer = None
        
        if TORCH_AVAILABLE:
            self._initialize_networks()
        else:
            logger.info("PyTorch not available - using traditional reinforcement learning")
    
    def _initialize_action_space(self) -> List[Dict]:
        """
        Initialize the action space with diverse attack vectors
        
        Returns:
            list: List of action dictionaries
        """
        # Create basic action space with standard attacks
        action_space = [
            # Deauthentication strategies
            {'vector': 'deauth', 'count': 1, 'reason': 1, 'burst': 1, 'interval': 0.2},
            {'vector': 'deauth', 'count': 3, 'reason': 2, 'burst': 1, 'interval': 0.15},
            {'vector': 'deauth', 'count': 8, 'reason': 7, 'burst': 1, 'interval': 0.1},
            {'vector': 'deauth', 'count': 12, 'reason': 3, 'burst': 2, 'interval': 0.1},
            
            # Disassociation strategies
            {'vector': 'disassoc', 'count': 3, 'reason': 1, 'burst': 1, 'interval': 0.18},
            {'vector': 'disassoc', 'count': 6, 'reason': 4, 'burst': 1, 'interval': 0.14},
            {'vector': 'disassoc', 'count': 12, 'reason': 7, 'burst': 2, 'interval': 0.12},
            
            # Mixed strategies
            {'vector': 'mixed', 'count': 4, 'reason': 7, 'burst': 1, 'interval': 0.15},
            {'vector': 'mixed', 'count': 8, 'reason': 3, 'burst': 2, 'interval': 0.12},
            
            # Alternative vectors
            {'vector': 'null_func', 'count': 4, 'burst': 1, 'interval': 0.2},
            {'vector': 'auth_flood', 'count': 6, 'burst': 1, 'interval': 0.15},
            {'vector': 'probe_flood', 'count': 5, 'burst': 1, 'interval': 0.18},
            {'vector': 'pmf_bypass', 'count': 4, 'reason': 9, 'burst': 1, 'interval': 0.2},
            {'vector': 'action_flood', 'count': 5, 'burst': 1, 'interval': 0.16}
        ]
        
        # Extend with specific strategies for different device categories
        for category, config in DEVICE_CATEGORIES.items():
            # Skip DEFAULT as we'll already have generic actions
            if category == "DEFAULT":
                continue
                
            # Add category-specific strategies
            vectors = config.get('attack_vector', [ATTACK_VECTORS["DEAUTH"]])
            reasons = config.get('reason_codes', [1, 7])
            
            for vector in vectors:
                vector_name = next((k for k, v in ATTACK_VECTORS.items() if v == vector), "deauth")
                for reason in reasons[:2]:  # Just use a couple of reasons to avoid too many actions
                    action = {
                        'vector': vector_name.lower(),
                        'count': config.get('burst', 5),
                        'reason': reason,
                        'burst': 1,
                        'interval': config.get('interval', 0.15),
                        'category': category
                    }
                    
                    # Check if this action is already in the space (avoid duplicates)
                    if not any(self._action_similarity(action, existing) > 0.9 for existing in action_space):
                        action_space.append(action)
        
        return action_space
    
    def _initialize_networks(self):
        """Initialize neural networks if PyTorch is available"""
        if not TORCH_AVAILABLE:
            return
            
        try:
            # Initialize policy and target networks
            input_dim = len(self.feature_names)
            output_dim = len(self.action_space)
            
            self.policy_network = DeepQNetwork(input_dim, output_dim).to(self.device)
            self.target_network = DeepQNetwork(input_dim, output_dim).to(self.device)
            
            # Initialize target network with policy network weights
            self.target_network.load_state_dict(self.policy_network.state_dict())
            self.target_network.eval()  # Target network is not trained directly
            
            # Initialize optimizer
            self.optimizer = optim.Adam(self.policy_network.parameters(), lr=self.learning_rate)
            
            # Initialize sequence model
            seq_input_dim = input_dim + output_dim + 1  # state features + action one-hot + reward
            self.sequence_model = SequenceModel(seq_input_dim).to(self.device)
            self.sequence_optimizer = optim.Adam(self.sequence_model.parameters(), lr=self.learning_rate)
            
            logger.info(f"Neural networks initialized on device: {self.device}")
            
        except Exception as e:
            logger.error(f"Error initializing neural networks: {e}")
            self.policy_network = None
            self.target_network = None
            self.sequence_model = None
    
    def set_attack_preference(self, preference: str):
        """
        Set attack preference to adjust reward calculation
        
        Args:
            preference: Attack preference ('balanced', 'stealth', 'speed', 'efficiency')
        """
        valid_preferences = ['balanced', 'stealth', 'speed', 'efficiency']
        if preference in valid_preferences:
            self.attack_preference = preference
            logger.info(f"Attack preference set to '{preference}'")
        else:
            logger.warning(f"Invalid attack preference '{preference}', using 'balanced'")
            self.attack_preference = 'balanced'
    
    def update_client_profile(self, client_mac: str, profile: Dict):
        """
        Update or create client profile with fingerprinting information
        
        Args:
            client_mac: Client MAC address
            profile: Client profile information
        """
        if client_mac not in self.client_states:
            self.client_states[client_mac] = {
                'last_seen': time.time(),
                'first_seen': time.time(),
                'attack_count': 0,
                'success_count': 0,
                'reconnect_count': 0,
                'reconnect_times': [],
                'signal_strength': -50,  # Default value
                'protection_level': 0,
                'device_category': profile.get('category', 'DEFAULT'),
                'vendor': profile.get('vendor', 'Unknown'),
                'protocols': profile.get('protocols', set()),
                'capabilities': profile.get('capabilities', set()),
                'pmf_detected': profile.get('pmf_detected', False),
                'activity_level': 0.5,  # Default value
                'last_action': None,
                'last_reward': 0.0,
                'current_state': None
            }
        else:
            # Update existing state with profile information
            self.client_states[client_mac].update({
                'device_category': profile.get('category', self.client_states[client_mac].get('device_category', 'DEFAULT')),
                'vendor': profile.get('vendor', self.client_states[client_mac].get('vendor', 'Unknown')),
                'protocols': profile.get('protocols', self.client_states[client_mac].get('protocols', set())),
                'capabilities': profile.get('capabilities', self.client_states[client_mac].get('capabilities', set())),
                'pmf_detected': profile.get('pmf_detected', self.client_states[client_mac].get('pmf_detected', False))
            })
            
            # Update protection level if PMF was detected
            if profile.get('pmf_detected', False):
                if 'PMF_required' in profile.get('capabilities', set()):
                    self.client_states[client_mac]['protection_level'] = 2  # PMF required
                else:
                    self.client_states[client_mac]['protection_level'] = 1  # PMF capable
            
            # Update signal strength if available
            if 'signal_strength' in profile:
                self.client_states[client_mac]['signal_strength'] = profile['signal_strength']
    
    def select_action(self, client_mac: str) -> Dict:
        """
        Select an action for a client using the policy
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Selected action
        """
        # If no state for this client, create one
        if client_mac not in self.client_states:
            self.client_states[client_mac] = {
                'last_seen': time.time(),
                'first_seen': time.time(),
                'attack_count': 0,
                'success_count': 0,
                'reconnect_count': 0,
                'device_category': 'DEFAULT',
                'signal_strength': -50,
                'protection_level': 0,
                'activity_level': 0.5,
                'last_action': None,
                'last_reward': 0.0,
                'current_state': None
            }
        
        # Extract client state
        client_state = self.client_states[client_mac]
        
        # Get current exploration rate (decreases over time)
        current_exploration = max(0.05, self.exploration_rate * math.exp(-0.01 * client_state.get('attack_count', 0)))
        
        # Integrate temporal pattern information if available
        delay = 0
        if self.pattern_miner:
            timing = self.pattern_miner.get_optimal_attack_timing(client_mac)
            if timing and timing.get('recommendation') == 'delayed':
                delay = timing.get('delay', 0)
        
        # Generate state features
        state_features = self._extract_state_features(client_mac)
        client_state['current_state'] = state_features
        
        # Select action
        if TORCH_AVAILABLE and self.policy_network and random.random() > current_exploration:
            # Use neural network to select action
            action_idx = self._select_action_with_network(state_features)
            logger.debug(f"Selected action {action_idx} using neural network for {client_mac}")
        else:
            # Use epsilon-greedy approach
            if random.random() < current_exploration:
                # Exploration: select random action
                action_idx = random.randint(0, len(self.action_space) - 1)
                logger.debug(f"Exploring with random action {action_idx} for {client_mac}")
            else:
                # Exploitation: select best action based on previous results
                action_idx = self._select_best_action(client_mac)
                logger.debug(f"Exploiting with best action {action_idx} for {client_mac}")
        
        # Get the action
        action = self.action_space[action_idx].copy()
        
        # Add action index and timing information
        action['action_idx'] = action_idx
        
        # Add timing information
        if delay > 0:
            action['delay'] = delay
        
        # Record as last selected action
        client_state['last_action'] = action
        
        # Update action stats
        self.action_stats[action_idx]['last_used'] = time.time()
        
        return action
    
    def _select_action_with_network(self, state_features: Dict) -> int:
        """
        Select action using neural network
        
        Args:
            state_features: State features dictionary
            
        Returns:
            int: Selected action index
        """
        if not TORCH_AVAILABLE or not self.policy_network:
            return random.randint(0, len(self.action_space) - 1)
            
        try:
            # Convert features to tensor
            state_tensor = self._features_to_tensor(state_features)
            
            # Get Q-values from policy network
            with torch.no_grad():
                q_values = self.policy_network(state_tensor)
            
            # Select action with highest Q-value
            return torch.argmax(q_values).item()
            
        except Exception as e:
            logger.error(f"Error selecting action with network: {e}")
            return random.randint(0, len(self.action_space) - 1)
    
    def _select_best_action(self, client_mac: str) -> int:
        """
        Select best action based on previous results
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            int: Selected action index
        """
        client_state = self.client_states[client_mac]
        
        # Get device category and check for category preferences
        category = client_state.get('device_category', 'DEFAULT')
        
        # Check if we have preferred actions for this category
        if (category in self.category_preferences and 
            self.category_preferences[category] and 
            random.random() < 0.7):  # 70% chance to use category preference
            
            # Select from category preferences, weighted by effectiveness
            preferences = self.category_preferences[category]
            actions = list(preferences.keys())
            weights = [preferences[a] for a in actions]
            
            # Normalize weights
            total_weight = sum(weights)
            if total_weight > 0:
                weights = [w / total_weight for w in weights]
                return random.choices(actions, weights=weights)[0]
        
        # Check protection level
        protection_level = client_state.get('protection_level', 0)
        
        # For protected devices, prioritize PMF bypass techniques
        if protection_level > 0 and random.random() < 0.8:
            pmf_actions = [i for i, a in enumerate(self.action_space) 
                         if a.get('vector') in ['pmf_bypass', 'action_flood']]
            if pmf_actions:
                return random.choice(pmf_actions)
        
        # Get action stats
        action_metrics = []
        for idx, stats in self.action_stats.items():
            if idx >= len(self.action_space):
                continue
                
            # Calculate action score - combination of reward and exploration bonus
            attempts = stats['attempt_count']
            if attempts == 0:
                # Prioritize untried actions
                score = 1.0
            else:
                # Use UCB1 formula: average reward + exploration bonus
                exploration_bonus = math.sqrt(2 * math.log(
                    client_state.get('attack_count', 0) + 1) / attempts)
                score = stats['avg_reward'] + 0.2 * exploration_bonus
            
            action_metrics.append((idx, score))
        
        # Select action with highest score
        if action_metrics:
            return max(action_metrics, key=lambda x: x[1])[0]
        
        # Fallback to random
        return random.randint(0, len(self.action_space) - 1)
    
    def update_with_action(self, client_mac: str, action: Dict):
        """
        Update engine with information about a selected action
        
        Args:
            client_mac: Client MAC address
            action: Selected action
        """
        if client_mac not in self.client_states:
            return
            
        # Get action index
        action_idx = action.get('action_idx')
        if action_idx is None:
            return
        
        # Update action attempt count
        if action_idx in self.action_stats:
            self.action_stats[action_idx]['attempt_count'] += 1
        
        # Update vector stats
        vector = action.get('vector')
        if vector in self.vector_stats:
            self.vector_stats[vector]['attempt_count'] += 1
        
        # Update client attack count
        self.client_states[client_mac]['attack_count'] += 1
    
    def update_with_result(self, client_mac: str, success: bool, reconnect_time: float = None):
        """
        Update engine with the result of an action
        
        Args:
            client_mac: Client MAC address
            success: Whether the action was successful
            reconnect_time: Reconnect time if client reconnected
        """
        if client_mac not in self.client_states:
            return
            
        client_state = self.client_states[client_mac]
        last_action = client_state.get('last_action')
        
        if not last_action:
            return
            
        # Get action metrics
        action_idx = last_action.get('action_idx')
        if action_idx is None or action_idx >= len(self.action_space):
            return
            
        # Calculate reward
        reward = self._calculate_reward(client_mac, success, reconnect_time)
        
        # Update client state
        if success:
            client_state['success_count'] += 1
        else:
            client_state['reconnect_count'] += 1
            if reconnect_time is not None:
                client_state['reconnect_times'].append(reconnect_time)
        
        # Record last reward
        client_state['last_reward'] = reward
        
        # Update action statistics
        if action_idx in self.action_stats:
            stats = self.action_stats[action_idx]
            stats['total_reward'] += reward
            stats['attempt_count'] = max(1, stats['attempt_count'])  # Ensure not zero
            
            # Update success count
            if success:
                stats['success_count'] += 1
            
            # Update average reward using exponential moving average
            alpha = 0.2  # Weight for new reward
            stats['avg_reward'] = (1 - alpha) * stats['avg_reward'] + alpha * reward
            
            # Update success rate
            stats['success_rate'] = stats['success_count'] / stats['attempt_count']
        
        # Update vector statistics
        vector = last_action.get('vector')
        if vector in self.vector_stats:
            self.vector_stats[vector]['attempt_count'] = max(1, self.vector_stats[vector]['attempt_count'])
            if success:
                self.vector_stats[vector]['success_count'] += 1
            self.vector_stats[vector]['success_rate'] = (
                self.vector_stats[vector]['success_count'] / self.vector_stats[vector]['attempt_count']
            )
        
        # Update category preferences
        category = client_state.get('device_category', 'DEFAULT')
        if category not in self.category_preferences:
            self.category_preferences[category] = {}
            
        if success and reward > 0.5:
            # Increase preference for this action
            current_value = self.category_preferences[category].get(action_idx, 0)
            self.category_preferences[category][action_idx] = current_value + reward
            
            # Normalize preferences (keep sum <= 10)
            total = sum(self.category_preferences[category].values())
            if total > 10:
                scale = 10 / total
                self.category_preferences[category] = {
                    k: v * scale for k, v in self.category_preferences[category].items()
                }
        
        # Add to history for training
        self.action_history[client_mac].append((last_action, reward))
        
        # Store sequence data for LSTM training
        state = client_state.get('current_state')
        if state:
            self.sequence_data[client_mac].append((state, action_idx, reward))
            # Limit sequence length
            if len(self.sequence_data[client_mac]) > 20:
                self.sequence_data[client_mac] = self.sequence_data[client_mac][-20:]
        
        # Train models if sufficient data
        if TORCH_AVAILABLE and self.policy_network:
            self._train_models()
    
    def _calculate_reward(self, client_mac: str, success: bool, reconnect_time: float = None) -> float:
        """
        Calculate reward for an action based on result
        
        Args:
            client_mac: Client MAC address
            success: Whether the action was successful
            reconnect_time: Reconnect time if client reconnected
            
        Returns:
            float: Calculated reward
        """
        client_state = self.client_states[client_mac]
        last_action = client_state.get('last_action', {})
        
        # Base reward based on success
        if success:
            base_reward = 1.0
        else:
            # Higher penalty for client with high reconnect count (resilient)
            reconnect_count = client_state.get('reconnect_count', 0)
            reconnect_penalty = min(0.5, 0.1 * reconnect_count)
            base_reward = -0.2 - reconnect_penalty
        
        # Define weights based on preference
        weights = {
            'efficiency': 0.2,  # Efficiency (less packets)
            'speed': 0.2,       # Speed (reconnect time)
            'stealth': 0.2,     # Stealth (evasion)
            'novelty': 0.1      # Novelty bonus
        }
        
        # Adjust weights based on preference
        if self.attack_preference == 'efficiency':
            weights['efficiency'] = 0.5
            weights['speed'] = 0.1
            weights['stealth'] = 0.1
        elif self.attack_preference == 'speed':
            weights['speed'] = 0.5
            weights['efficiency'] = 0.1
            weights['stealth'] = 0.1
        elif self.attack_preference == 'stealth':
            weights['stealth'] = 0.5
            weights['efficiency'] = 0.1
            weights['speed'] = 0.1
        
        if success:
            # 1. Efficiency bonus
            packet_count = last_action.get('count', 8) * last_action.get('burst', 1)
            efficiency_bonus = weights['efficiency'] * min(1.0, 10.0 / max(1, packet_count))
            
            # Add efficiency bonus to reward
            base_reward += efficiency_bonus
        elif reconnect_time is not None:
            # 2. Reconnect time bonus (longer reconnect is better)
            max_reconnect_time = 30.0  # Cap at 30 seconds
            normalized_time = min(1.0, reconnect_time / max_reconnect_time)
            time_bonus = weights['speed'] * normalized_time
            
            # Add time bonus to reward
            base_reward += time_bonus
        
        # 3. Stealth bonus/penalty based on packet count and rate
        vector = last_action.get('vector', 'deauth')
        count = last_action.get('count', 8)
        
        # More packets and deauth/disassoc are less stealthy
        if vector in ['deauth', 'disassoc'] and count > 5:
            stealth_penalty = weights['stealth'] * (count / 20.0)
            base_reward -= stealth_penalty
        elif vector in ['null_func', 'action_flood']:
            # More stealthy vectors get bonus
            stealth_bonus = weights['stealth'] * 0.5
            base_reward += stealth_bonus
        
        # 4. Novelty bonus for less used actions
        action_idx = last_action.get('action_idx')
        if action_idx is not None and action_idx in self.action_stats:
            attempts = self.action_stats[action_idx]['attempt_count']
            if attempts <= 3:  # Rarely used
                novelty_bonus = weights['novelty']
                base_reward += novelty_bonus
        
        # Clamp reward to reasonable range
        return max(-1.0, min(1.5, base_reward))
    
    def _extract_state_features(self, client_mac: str) -> Dict:
        """
        Extract features from client state for decision making
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Dictionary of state features
        """
        client_state = self.client_states[client_mac]
        current_time = time.time()
        
        # Convert device category to numeric value
        categories = list(DEVICE_CATEGORIES.keys())
        category = client_state.get('device_category', 'DEFAULT')
        category_idx = categories.index(category) if category in categories else 0
        category_norm = category_idx / max(1, len(categories) - 1)
        
        # Extract and normalize features
        features = {
            'device_category': category_norm,
            'signal_strength': (client_state.get('signal_strength', -50) + 100) / 100,  # Normalize -100..0 to 0..1
            'protection_level': client_state.get('protection_level', 0) / 2.0,  # 0, 0.5, or 1.0
            'reconnect_count': min(1.0, client_state.get('reconnect_count', 0) / 10.0),
            'attack_count': min(1.0, client_state.get('attack_count', 0) / 20.0),
            'success_rate': (client_state.get('success_count', 0) / 
                          max(1, client_state.get('attack_count', 0))),
            'time_since_last_seen': min(1.0, (current_time - client_state.get('last_seen', current_time)) / 60.0),
            'client_activity': client_state.get('activity_level', 0.5),
            'time_of_day': (datetime.now().hour * 60 + datetime.now().minute) / (24 * 60),
            'channel': 0.5  # Default channel normalization
        }
        
        return features
    
    def _features_to_tensor(self, features: Dict) -> torch.Tensor:
        """
        Convert features dictionary to tensor
        
        Args:
            features: Dictionary of features
            
        Returns:
            torch.Tensor: Feature tensor
        """
        if not TORCH_AVAILABLE:
            return None
            
        # Extract features in consistent order
        values = [features.get(name, 0.0) for name in self.feature_names]
        return torch.FloatTensor(values).unsqueeze(0).to(self.device)
    
    def _train_models(self):
        """Train neural network models with collected data"""
        if not TORCH_AVAILABLE or not self.policy_network:
            return
            
        # Collect training data from all clients
        states = []
        actions = []
        rewards = []
        next_states = []
        dones = []
        
        for client_mac, history in self.action_history.items():
            if len(history) < 2:
                continue
                
            # Get client state
            client_state = self.client_states.get(client_mac)
            if not client_state:
                continue
                
            # Extract last few actions for training
            for i in range(min(10, len(history) - 1)):
                idx = len(history) - 2 - i  # Start from second last and go backwards
                if idx < 0:
                    break
                    
                action_tuple = history[idx]
                next_action_tuple = history[idx + 1]
                
                # Extract data
                action = action_tuple[0]
                reward = action_tuple[1]
                action_idx = action.get('action_idx')
                
                # Skip if no valid action index
                if action_idx is None or action_idx >= len(self.action_space):
                    continue
                
                # Use client's current state as an approximation
                # In a real system, we would store state with each action
                current_state = self._extract_state_features(client_mac)
                next_state = self._extract_state_features(client_mac)
                
                # Add to training data
                states.append(current_state)
                actions.append(action_idx)
                rewards.append(reward)
                next_states.append(next_state)
                dones.append(False)  # Never done in this context
        
        # Need at least a batch of data
        if len(states) < 8:
            return
            
        # Convert to tensors
        state_tensors = [self._features_to_tensor(state) for state in states]
        if not state_tensors:
            return
            
        state_batch = torch.cat(state_tensors)
        action_batch = torch.LongTensor(actions).unsqueeze(1).to(self.device)
        reward_batch = torch.FloatTensor(rewards).to(self.device)
        next_state_tensors = [self._features_to_tensor(state) for state in next_states]
        
        if not next_state_tensors:
            return
            
        next_state_batch = torch.cat(next_state_tensors)
        done_batch = torch.FloatTensor(dones).to(self.device)
        
        # Compute current Q values
        current_q_values = self.policy_network(state_batch).gather(1, action_batch)
        
        # Compute next Q values using target network
        with torch.no_grad():
            next_q_values = self.target_network(next_state_batch).max(1)[0]
            target_q_values = reward_batch + (1 - done_batch) * self.discount_factor * next_q_values
        
        # Compute loss and optimize
        loss = F.smooth_l1_loss(current_q_values, target_q_values.unsqueeze(1))
        
        self.optimizer.zero_grad()
        loss.backward()
        
        # Clip gradients to prevent exploding gradients
        for param in self.policy_network.parameters():
            param.grad.data.clamp_(-1, 1)
            
        self.optimizer.step()
        
        # Periodically update target network
        with torch.no_grad():
            target_net_state_dict = self.target_network.state_dict()
            policy_net_state_dict = self.policy_network.state_dict()
            
            # Soft update
            tau = 0.01
            for key in policy_net_state_dict:
                target_net_state_dict[key] = (
                    policy_net_state_dict[key] * tau + target_net_state_dict[key] * (1 - tau)
                )
            self.target_network.load_state_dict(target_net_state_dict)
        
        # Train sequence model
        self._train_sequence_model()
        
        logger.debug(f"Trained neural networks with {len(states)} samples, loss: {loss.item():.4f}")
    
    def _train_sequence_model(self):
        """Train sequence model with collected sequence data"""
        if not TORCH_AVAILABLE or not self.sequence_model:
            return
            
        # Collect sequence data from all clients
        sequences = []
        labels = []
        
        for client_mac, seq_data in self.sequence_data.items():
            if len(seq_data) < 5:  # Need a minimum sequence length
                continue
                
            # Create sequences with sliding window
            window_size = 4
            for i in range(len(seq_data) - window_size):
                # Extract window
                window = seq_data[i:i+window_size]
                
                # Extract features, actions, and rewards
                window_features = []
                for state, action_idx, reward in window:
                    # Create joint feature vector: state + one-hot action + reward
                    feature_values = [state.get(name, 0.0) for name in self.feature_names]
                    action_one_hot = [0.0] * len(self.action_space)
                    if 0 <= action_idx < len(self.action_space):
                        action_one_hot[action_idx] = 1.0
                    joint_features = feature_values + action_one_hot + [reward]
                    window_features.append(joint_features)
                
                # Get next reward as label
                next_reward = seq_data[i+window_size][2]
                
                sequences.append(window_features)
                labels.append(1.0 if next_reward > 0 else 0.0)  # Binary success prediction
        
        # Need at least a few sequences
        if len(sequences) < 4:
            return
            
        # Convert to tensors
        seq_tensor = torch.FloatTensor(sequences).to(self.device)
        label_tensor = torch.FloatTensor(labels).to(self.device)
        
        # Train the sequence model
        self.sequence_model.train()
        self.sequence_optimizer.zero_grad()
        
        # Forward pass
        outputs, _ = self.sequence_model(seq_tensor)
        outputs = outputs.squeeze(1)
        
        # Binary cross entropy loss
        loss = F.binary_cross_entropy_with_logits(outputs, label_tensor)
        
        # Backward pass
        loss.backward()
        self.sequence_optimizer.step()
        
        logger.debug(f"Trained sequence model with {len(sequences)} sequences, loss: {loss.item():.4f}")
    
    def predict_success_probability(self, client_mac: str, action_idx: int) -> float:
        """
        Predict probability of success for an action
        
        Args:
            client_mac: Client MAC address
            action_idx: Action index
            
        Returns:
            float: Success probability (0.0 to 1.0)
        """
        # First check action stats
        if action_idx in self.action_stats and self.action_stats[action_idx]['attempt_count'] > 0:
            return self.action_stats[action_idx]['success_rate']
        
        # If no stats, check vector stats
        if action_idx < len(self.action_space):
            vector = self.action_space[action_idx].get('vector')
            if vector in self.vector_stats and self.vector_stats[vector]['attempt_count'] > 0:
                return self.vector_stats[vector]['success_rate']
        
        # Fallback to default
        return 0.5
    
    def _action_similarity(self, action1: Dict, action2: Dict) -> float:
        """
        Calculate similarity between two actions
        
        Args:
            action1: First action
            action2: Second action
            
        Returns:
            float: Similarity score (0.0 to 1.0)
        """
        score = 0.0
        total_weight = 0.0
        
        # Define field weights
        weights = {
            'vector': 0.5,
            'count': 0.2,
            'reason': 0.1,
            'burst': 0.1,
            'interval': 0.1
        }
        
        # Vector similarity (exact match)
        if action1.get('vector') == action2.get('vector'):
            score += weights['vector']
        total_weight += weights['vector']
        
        # Count similarity (relative)
        count1 = action1.get('count', 0)
        count2 = action2.get('count', 0)
        if count1 > 0 and count2 > 0:
            ratio = min(count1, count2) / max(count1, count2)
            score += weights['count'] * ratio
        total_weight += weights['count']
        
        # Reason similarity (exact match)
        if 'reason' in action1 and 'reason' in action2:
            if action1['reason'] == action2['reason']:
                score += weights['reason']
        total_weight += weights['reason']
        
        # Burst similarity (relative)
        burst1 = action1.get('burst', 1)
        burst2 = action2.get('burst', 1)
        if burst1 > 0 and burst2 > 0:
            ratio = min(burst1, burst2) / max(burst1, burst2)
            score += weights['burst'] * ratio
        total_weight += weights['burst']
        
        # Interval similarity (relative)
        interval1 = action1.get('interval', 0)
        interval2 = action2.get('interval', 0)
        if interval1 > 0 and interval2 > 0:
            ratio = min(interval1, interval2) / max(interval1, interval2)
            score += weights['interval'] * ratio
        total_weight += weights['interval']
        
        # Normalize score
        if total_weight > 0:
            score /= total_weight
            
        return score
    
    def get_optimized_strategy(self, client_mac: str) -> Dict:
        """
        Get an optimized strategy for a specific client based on analysis
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Optimized strategy
        """
        if client_mac not in self.client_states:
            return {}
            
        client_state = self.client_states[client_mac]
        
        # Check if client has reconnected multiple times
        reconnect_count = client_state.get('reconnect_count', 0)
        
        # Base strategy
        strategy = {
            'reason_codes': [1, 2, 7],
            'burst': 1,
            'interval': 0.15
        }
        
        # Add temporal optimization if available
        if self.pattern_miner:
            timing = self.pattern_miner.get_optimal_attack_timing(client_mac)
            if timing and timing.get('recommendation') == 'delayed':
                strategy['delay'] = timing.get('delay', 0)
                strategy['timing_strategy'] = 'delayed'
                strategy['expected_success_boost'] = timing.get('expected_success_boost', 0)
        
        # For resilient clients, try alternating vectors
        if reconnect_count >= 3:
            # Get best performing vectors
            best_vectors = sorted(
                self.vector_stats.items(),
                key=lambda x: x[1]['success_rate'],
                reverse=True
            )
            
            # Select top 3 vectors
            vectors = [v[0] for v in best_vectors[:3] if v[1]['attempt_count'] > 0]
            
            # Fallback if no vectors have been used
            if not vectors:
                vectors = ['deauth', 'disassoc', 'mixed']
                
            strategy['vectors'] = vectors
            strategy['burst'] = min(3, reconnect_count // 2)  # Increase burst based on reconnects
        
        # Check device protection level
        protection_level = client_state.get('protection_level', 0)
        if protection_level > 0:
            # For protected devices, prioritize PMF bypass techniques
            strategy['vectors'] = ['pmf_bypass', 'action_flood']
            strategy['reason_codes'] = [9, 10, 11]  # Less common reason codes
        
        # Adjust based on device category
        category = client_state.get('device_category', 'DEFAULT')
        if category in DEVICE_CATEGORIES:
            config = DEVICE_CATEGORIES[category]
            
            # Use category-specific parameters
            strategy['interval'] = config.get('interval', strategy.get('interval', 0.15))
            
            # Use category-specific reason codes if no protection
            if protection_level == 0:
                strategy['reason_codes'] = config.get('reason_codes', strategy.get('reason_codes', [1, 7]))
        
        # For aggressive mode, increase burst
        if self.attack_preference == 'speed':
            strategy['burst'] = max(2, strategy.get('burst', 1))
        
        # For stealth mode, reduce visibility
        if self.attack_preference == 'stealth':
            strategy['burst'] = 1
            strategy['interval'] = max(0.2, strategy.get('interval', 0.15) * 1.5)
            
            # Prioritize stealthier vectors
            stealth_vectors = ['null_func', 'action_flood', 'probe_flood']
            if 'vectors' not in strategy:
                strategy['vectors'] = stealth_vectors
        
        return strategy
    
    def get_strategy_insights(self) -> Dict:
        """
        Get insights into strategy effectiveness
        
        Returns:
            dict: Strategy insights data
        """
        # Calculate success rates for vectors
        vector_performance = {
            vector: stats['success_rate'] 
            for vector, stats in self.vector_stats.items() 
            if stats['attempt_count'] > 0
        }
        
        # Get best performing actions
        action_performance = []
        for idx, stats in self.action_stats.items():
            if idx >= len(self.action_space) or stats['attempt_count'] == 0:
                continue
                
            action_performance.append({
                'index': idx,
                'vector': self.action_space[idx].get('vector', 'unknown'),
                'count': self.action_space[idx].get('count', 0),
                'reason': self.action_space[idx].get('reason', 0),
                'success_rate': stats['success_rate'],
                'avg_reward': stats['avg_reward'],
                'attempts': stats['attempt_count']
            })
        
        # Sort by average reward
        action_performance.sort(key=lambda x: x['avg_reward'], reverse=True)
        
        # Calculate device category effectiveness
        category_effectiveness = {}
        for category, preferences in self.category_preferences.items():
            if preferences:
                # Calculate average effectiveness for this category
                effectiveness = sum(preferences.values()) / len(preferences)
                category_effectiveness[category] = effectiveness
        
        return {
            'vector_performance': vector_performance,
            'top_actions': action_performance[:5],  # Top 5 actions
            'category_effectiveness': category_effectiveness,
            'attack_preference': self.attack_preference
        }
    
    def save_state(self, path: str = None):
        """
        Save engine state to file
        
        Args:
            path: File path to save to (default: save_dir/cognitive_state.json)
        """
        if not path and not self.save_dir:
            logger.warning("No save path specified")
            return
            
        save_path = path or os.path.join(self.save_dir, 'cognitive_state.json')
        
        try:
            # Prepare data for serialization
            state = {
                'action_stats': self.action_stats,
                'vector_stats': self.vector_stats,
                'category_preferences': self.category_preferences,
                'attack_preference': self.attack_preference
            }
            
            # Convert sets to lists for serialization
            for client_mac, client_state in self.client_states.items():
                if 'protocols' in client_state and isinstance(client_state['protocols'], set):
                    client_state['protocols'] = list(client_state['protocols'])
                if 'capabilities' in client_state and isinstance(client_state['capabilities'], set):
                    client_state['capabilities'] = list(client_state['capabilities'])
            
            # Save to file
            with open(save_path, 'w') as f:
                json.dump(state, f, indent=2)
                
            logger.info(f"Saved cognitive engine state to {save_path}")
            
            # Save neural network models if available
            if TORCH_AVAILABLE and self.policy_network:
                model_path = os.path.join(self.save_dir, 'policy_network.pt')
                torch.save(self.policy_network.state_dict(), model_path)
                
                if self.sequence_model:
                    seq_model_path = os.path.join(self.save_dir, 'sequence_model.pt')
                    torch.save(self.sequence_model.state_dict(), seq_model_path)
                    
                logger.info(f"Saved neural network models to {self.save_dir}")
                
        except Exception as e:
            logger.error(f"Error saving cognitive engine state: {e}")
    
    def load_state(self, path: str = None):
        """
        Load engine state from file
        
        Args:
            path: File path to load from (default: save_dir/cognitive_state.json)
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        if not path and not self.save_dir:
            logger.warning("No load path specified")
            return False
            
        load_path = path or os.path.join(self.save_dir, 'cognitive_state.json')
        
        try:
            # Check if file exists
            if not os.path.exists(load_path):
                logger.warning(f"State file not found: {load_path}")
                return False
                
            # Load from file
            with open(load_path, 'r') as f:
                state = json.load(f)
                
            # Restore state
            if 'action_stats' in state:
                self.action_stats = state['action_stats']
            if 'vector_stats' in state:
                self.vector_stats = state['vector_stats']
            if 'category_preferences' in state:
                self.category_preferences = state['category_preferences']
            if 'attack_preference' in state:
                self.attack_preference = state['attack_preference']
                
            logger.info(f"Loaded cognitive engine state from {load_path}")
            
            # Load neural network models if available
            if TORCH_AVAILABLE and self.policy_network:
                model_path = os.path.join(self.save_dir, 'policy_network.pt')
                if os.path.exists(model_path):
                    self.policy_network.load_state_dict(torch.load(model_path, map_location=self.device))
                    self.target_network.load_state_dict(self.policy_network.state_dict())
                    
                seq_model_path = os.path.join(self.save_dir, 'sequence_model.pt')
                if os.path.exists(seq_model_path) and self.sequence_model:
                    self.sequence_model.load_state_dict(torch.load(seq_model_path, map_location=self.device))
                    
                logger.info(f"Loaded neural network models from {self.save_dir}")
                
            return True
            
        except Exception as e:
            logger.error(f"Error loading cognitive engine state: {e}")
            return False