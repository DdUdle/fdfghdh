"""
Wireless Network Analysis Framework - Strategy Optimizer

This module implements advanced attack strategy optimization using
evolutionary algorithms, heuristic search, and reinforcement learning.
"""

import os
import time
import random
import logging
import math
import copy
import hashlib
from typing import Dict, List, Tuple, Optional, Union, Any, Callable

# Try to import numpy for numerical operations
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

from ..utils.logging import setup_logger
from ..core.constants import ATTACK_VECTORS, DEAUTH_REASON_CODES, DEVICE_CATEGORIES

# Configure logger
logger = setup_logger(__name__)

class StrategyOptimizer:
    """
    Optimizes attack strategies using evolutionary algorithms, multi-armed bandits,
    and reinforcement learning techniques.
    """
    
    def __init__(self, strategy_space: List[Dict] = None, learning_rate: float = 0.05,
                exploration_rate: float = 0.2, discount_factor: float = 0.9):
        """
        Initialize the strategy optimizer
        
        Args:
            strategy_space: List of possible strategies (default: None, auto-generated)
            learning_rate: Learning rate for model updates
            exploration_rate: Exploration rate for new strategies
            discount_factor: Discount factor for future rewards
        """
        self.learning_rate = learning_rate
        self.exploration_rate = exploration_rate
        self.discount_factor = discount_factor
        
        # Generate strategy space if not provided
        self.strategy_space = strategy_space or self._generate_strategy_space()
        
        # Performance tracking
        self.strategy_performance = {}  # Strategy hash -> performance metrics
        self.device_strategies = {}     # Device category -> list of good strategies
        self.client_results = {}        # Client MAC -> list of (strategy_hash, result) tuples
        
        # Stats counters
        self.calls = 0
        self.successful_attacks = 0
        self.failed_attacks = 0
        
        # Evolution parameters
        self.population_size = 20
        self.mutation_rate = 0.3
        self.crossover_rate = 0.7
        
        # Initialize strategy population
        self._initialize_population()
    
    def _generate_strategy_space(self) -> List[Dict]:
        """
        Generate a diverse strategy space
        
        Returns:
            list: List of strategy dictionaries
        """
        strategy_space = []
        
        # Generate basic strategies
        for vector_name, vector_id in ATTACK_VECTORS.items():
            # Skip abstract vector types
            if vector_name == 'MIXED':
                continue
                
            # Create strategies with different parameters
            for count in [3, 5, 8, 12]:
                # For vectors that use reason codes
                if vector_name in ['DEAUTH', 'DISASSOC', 'PMF_BYPASS']:
                    for reason in list(DEAUTH_REASON_CODES.keys())[:5]:  # Use first 5 reason codes
                        for burst in [1, 2, 3]:
                            for interval in [0.1, 0.15, 0.2]:
                                strategy = {
                                    'vector': vector_name.lower(),
                                    'count': count,
                                    'reason': reason,
                                    'burst': burst,
                                    'interval': interval
                                }
                                strategy_space.append(strategy)
                # For vectors without reason codes
                else:
                    for burst in [1, 2, 3]:
                        for interval in [0.1, 0.15, 0.2]:
                            strategy = {
                                'vector': vector_name.lower(),
                                'count': count,
                                'burst': burst,
                                'interval': interval
                            }
                            strategy_space.append(strategy)
        
        # Add category-specific strategies from constants
        for category, config in DEVICE_CATEGORIES.items():
            # Skip DEFAULT category as we already have generic strategies
            if category == "DEFAULT":
                continue
                
            for vector_id in config.get('attack_vector', [ATTACK_VECTORS["DEAUTH"]]):
                # Get vector name from ID
                vector_name = next((k for k, v in ATTACK_VECTORS.items() if v == vector_id), "DEAUTH").lower()
                
                for reason in config.get('reason_codes', [1, 7])[:2]:  # Use first 2 reason codes
                    strategy = {
                        'vector': vector_name,
                        'count': config.get('burst', 5),
                        'reason': reason,
                        'burst': 1,
                        'interval': config.get('interval', 0.15),
                        'category': category
                    }
                    strategy_space.append(strategy)
        
        # Create mixed strategies
        mixed_strategies = []
        for _ in range(10):  # Add 10 mixed strategies
            # Select two random vectors
            vectors = random.sample(list(ATTACK_VECTORS.keys()), 2)
            vectors = [v.lower() for v in vectors if v != 'MIXED']
            
            strategy = {
                'vector': 'mixed',
                'vectors': vectors,
                'count': random.choice([4, 6, 8]),
                'reason': random.choice(list(DEAUTH_REASON_CODES.keys())),
                'burst': random.choice([1, 2]),
                'interval': random.choice([0.1, 0.15, 0.2])
            }
            mixed_strategies.append(strategy)
        
        # Add mixed strategies to space
        strategy_space.extend(mixed_strategies)
        
        logger.info(f"Generated strategy space with {len(strategy_space)} strategies")
        return strategy_space
    
    def _initialize_population(self):
        """Initialize the strategy population"""
        # If we have a large strategy space, select a diverse subset for initial population
        if len(self.strategy_space) > self.population_size:
            # Group by vector type
            vector_groups = {}
            for strategy in self.strategy_space:
                vector = strategy['vector']
                if vector not in vector_groups:
                    vector_groups[vector] = []
                vector_groups[vector].append(strategy)
            
            # Select strategies from each vector group
            population = []
            vectors = list(vector_groups.keys())
            while len(population) < self.population_size and vectors:
                # Cycle through vector types
                for vector in vectors[:]:
                    if vector_groups[vector]:
                        # Pick a random strategy from this vector group
                        strategy = random.choice(vector_groups[vector])
                        population.append(strategy)
                        # Remove the selected strategy
                        vector_groups[vector].remove(strategy)
                    else:
                        # No more strategies of this type
                        vectors.remove(vector)
                    
                    # Stop if we've reached the population size
                    if len(population) >= self.population_size:
                        break
            
            self.population = population
        else:
            # If strategy space is small, use the whole space
            self.population = copy.deepcopy(self.strategy_space)
        
        # Initialize performance metrics for each strategy
        for strategy in self.population:
            strategy_hash = self._hash_strategy(strategy)
            self.strategy_performance[strategy_hash] = {
                'attempts': 0,
                'successes': 0,
                'failures': 0,
                'total_reward': 0.0,
                'avg_reward': 0.0,
                'success_rate': 0.0,
                'last_used': 0,
                'ucb_score': 1.0  # Start optimistically
            }
    
    def _hash_strategy(self, strategy: Dict) -> str:
        """
        Create a unique hash for a strategy
        
        Args:
            strategy: Strategy dictionary
            
        Returns:
            str: Strategy hash
        """
        # Normalize and sort strategy items for consistent hashing
        strategy_items = sorted(strategy.items())
        
        # Convert to string
        strategy_str = str(strategy_items)
        
        # Create hash
        return hashlib.md5(strategy_str.encode()).hexdigest()[:12]
    
    def select_strategy(self, client_mac: str, device_category: str = None,
                      history: List[Dict] = None) -> Dict:
        """
        Select the best strategy for a client
        
        Args:
            client_mac: Client MAC address
            device_category: Device category (optional)
            history: Attack history for the client (optional)
            
        Returns:
            dict: Selected strategy
        """
        self.calls += 1
        
        # Explore with probability exploration_rate
        if random.random() < self.exploration_rate:
            # Exploration: try a random strategy
            strategy = self._select_exploration_strategy(client_mac, device_category)
            logger.debug(f"Exploring with strategy: {strategy['vector']}")
        else:
            # Exploitation: select best known strategy
            strategy = self._select_exploitation_strategy(client_mac, device_category, history)
            logger.debug(f"Exploiting with strategy: {strategy['vector']}")
        
        # Add a unique ID to the strategy for tracking
        strategy_hash = self._hash_strategy(strategy)
        strategy['id'] = strategy_hash
        
        # Record usage
        if strategy_hash in self.strategy_performance:
            self.strategy_performance[strategy_hash]['last_used'] = time.time()
            self.strategy_performance[strategy_hash]['attempts'] += 1
        
        return strategy
    
    def _select_exploration_strategy(self, client_mac: str, device_category: str = None) -> Dict:
        """
        Select a strategy for exploration
        
        Args:
            client_mac: Client MAC address
            device_category: Device category
            
        Returns:
            dict: Selected strategy
        """
        # Use category-specific strategies if available
        if device_category and device_category in self.device_strategies:
            category_strategies = self.device_strategies[device_category]
            if category_strategies and random.random() < 0.7:  # 70% chance to use category strategy
                return random.choice(category_strategies)
        
        # Try a random strategy from the current population
        if random.random() < 0.8:  # 80% chance to use population
            return random.choice(self.population)
        
        # Sometimes create a new strategy through mutation
        return self._create_mutated_strategy()
    
    def _select_exploitation_strategy(self, client_mac: str, device_category: str = None,
                                    history: List[Dict] = None) -> Dict:
        """
        Select the best strategy for exploitation
        
        Args:
            client_mac: Client MAC address
            device_category: Device category
            history: Attack history for the client
            
        Returns:
            dict: Selected strategy
        """
        # Use client-specific history if available
        if client_mac in self.client_results:
            client_history = self.client_results[client_mac]
            
            # If we have enough data, use it to select the best strategy
            if len(client_history) >= 3:
                # Group by strategy hash
                strategy_results = {}
                for s_hash, result in client_history:
                    if s_hash not in strategy_results:
                        strategy_results[s_hash] = {'success': 0, 'fail': 0, 'total': 0}
                    
                    strategy_results[s_hash]['total'] += 1
                    if result:
                        strategy_results[s_hash]['success'] += 1
                    else:
                        strategy_results[s_hash]['fail'] += 1
                
                # Calculate success rates
                for s_hash in strategy_results:
                    total = strategy_results[s_hash]['total']
                    success = strategy_results[s_hash]['success']
                    strategy_results[s_hash]['rate'] = success / total if total > 0 else 0
                
                # Find strategy with highest success rate
                best_hash = max(strategy_results, key=lambda x: strategy_results[x]['rate'])
                
                # Find the strategy in the population
                for strategy in self.population:
                    if self._hash_strategy(strategy) == best_hash:
                        return strategy
        
        # Use category-specific strategies if available
        if device_category and device_category in self.device_strategies:
            category_strategies = self.device_strategies[device_category]
            if category_strategies:
                return max(category_strategies, key=self._calculate_ucb_score)
        
        # Use UCB (Upper Confidence Bound) algorithm to balance exploitation and exploration
        if self.strategy_performance:
            return max(self.population, key=self._calculate_ucb_score)
        
        # Fallback to random strategy
        return random.choice(self.population)
    
    def _calculate_ucb_score(self, strategy: Dict) -> float:
        """
        Calculate UCB score for a strategy
        
        Args:
            strategy: Strategy dictionary
            
        Returns:
            float: UCB score
        """
        strategy_hash = self._hash_strategy(strategy)
        
        # Get performance metrics
        if strategy_hash not in self.strategy_performance:
            # Not seen before, return optimistic value
            return 2.0
        
        metrics = self.strategy_performance[strategy_hash]
        
        # If never attempted, return optimistic value
        if metrics['attempts'] == 0:
            return 2.0
        
        # Calculate UCB score
        exploitation = metrics['avg_reward']
        exploration = math.sqrt(2 * math.log(self.calls) / metrics['attempts'])
        
        # Combine scores with weight parameter
        return exploitation + self.exploration_rate * exploration
    
    def update_result(self, client_mac: str, strategy: Dict, success: bool, 
                     reward: float, device_category: str = None):
        """
        Update strategy performance with attack result
        
        Args:
            client_mac: Client MAC address
            strategy: Strategy used
            success: Whether the attack was successful
            reward: Reward value
            device_category: Device category
        """
        # Get strategy hash
        strategy_hash = strategy.get('id') or self._hash_strategy(strategy)
        
        # Update global stats
        if success:
            self.successful_attacks += 1
        else:
            self.failed_attacks += 1
        
        # Update client history
        if client_mac not in self.client_results:
            self.client_results[client_mac] = []
        
        self.client_results[client_mac].append((strategy_hash, success))
        
        # Cap client history length
        if len(self.client_results[client_mac]) > 50:
            self.client_results[client_mac] = self.client_results[client_mac][-50:]
        
        # Update strategy performance
        if strategy_hash in self.strategy_performance:
            metrics = self.strategy_performance[strategy_hash]
            
            # Update counts
            if success:
                metrics['successes'] += 1
            else:
                metrics['failures'] += 1
            
            # Update metrics
            metrics['total_reward'] += reward
            
            # Calculate new average using exponential moving average
            if metrics['attempts'] > 0:
                alpha = 0.1  # Low alpha for stability
                metrics['avg_reward'] = (1 - alpha) * metrics['avg_reward'] + alpha * reward
            else:
                metrics['avg_reward'] = reward
            
            # Update success rate
            metrics['success_rate'] = metrics['successes'] / max(1, metrics['attempts'])
        
        # Update device category strategies
        if device_category and success and reward > 0:
            # Add to category-specific strategies if not already there
            if device_category not in self.device_strategies:
                self.device_strategies[device_category] = []
            
            # Find strategy in population
            strategy_in_population = None
            for s in self.population:
                if self._hash_strategy(s) == strategy_hash:
                    strategy_in_population = s
                    break
            
            # Add to category strategies if not already there
            if strategy_in_population:
                category_strategies = self.device_strategies[device_category]
                if strategy_in_population not in category_strategies:
                    category_strategies.append(strategy_in_population)
        
        # Periodically evolve the population
        if (self.successful_attacks + self.failed_attacks) % 50 == 0:
            self._evolve_population()
    
    def _evolve_population(self):
        """Evolve the strategy population using genetic algorithm"""
        # Need at least a few data points to evolve
        if self.successful_attacks + self.failed_attacks < 10:
            return
        
        logger.debug("Evolving strategy population")
        
        # Calculate fitness for each strategy
        strategy_fitness = []
        for strategy in self.population:
            strategy_hash = self._hash_strategy(strategy)
            
            # Get performance metrics
            if strategy_hash in self.strategy_performance:
                metrics = self.strategy_performance[strategy_hash]
                
                # Calculate fitness (weighted sum of metrics)
                if metrics['attempts'] > 0:
                    # Components:
                    # - Success rate (higher is better)
                    # - Average reward (higher is better)
                    # - Attempt count (higher means more reliable estimate)
                    success_rate = metrics['successes'] / max(1, metrics['attempts'])
                    avg_reward = metrics['avg_reward']
                    attempt_bonus = min(1.0, metrics['attempts'] / 10.0)  # Max out at 10 attempts
                    
                    fitness = (0.5 * success_rate + 0.3 * max(0, avg_reward) + 0.2 * attempt_bonus)
                else:
                    # Never attempted, neutral fitness
                    fitness = 0.5
            else:
                # Never seen, neutral fitness
                fitness = 0.5
            
            strategy_fitness.append((strategy, fitness))
        
        # Sort by fitness (descending)
        strategy_fitness.sort(key=lambda x: x[1], reverse=True)
        
        # Keep top 30% as elite
        elite_count = max(2, int(0.3 * len(self.population)))
        elites = [s[0] for s in strategy_fitness[:elite_count]]
        
        # Create new population
        new_population = elites.copy()
        
        # Create offspring through crossover and mutation
        while len(new_population) < self.population_size:
            # Select parents using tournament selection
            parent1 = self._tournament_selection(strategy_fitness)
            parent2 = self._tournament_selection(strategy_fitness)
            
            # Crossover
            if random.random() < self.crossover_rate:
                child = self._crossover(parent1, parent2)
            else:
                # No crossover, use better parent
                child = parent1 if strategy_fitness[self.population.index(parent1)][1] > strategy_fitness[self.population.index(parent2)][1] else parent2
            
            # Mutation
            if random.random() < self.mutation_rate:
                child = self._mutate(child)
            
            # Add to new population
            new_population.append(child)
        
        # Update population
        self.population = new_population
        
        # Initialize performance metrics for new strategies
        for strategy in self.population:
            strategy_hash = self._hash_strategy(strategy)
            if strategy_hash not in self.strategy_performance:
                self.strategy_performance[strategy_hash] = {
                    'attempts': 0,
                    'successes': 0,
                    'failures': 0,
                    'total_reward': 0.0,
                    'avg_reward': 0.0,
                    'success_rate': 0.0,
                    'last_used': 0,
                    'ucb_score': 1.0  # Start optimistically
                }
    
    def _tournament_selection(self, strategy_fitness: List[Tuple[Dict, float]]) -> Dict:
        """
        Select a strategy using tournament selection
        
        Args:
            strategy_fitness: List of (strategy, fitness) tuples
            
        Returns:
            dict: Selected strategy
        """
        # Select 3 random strategies
        tournament = random.sample(strategy_fitness, min(3, len(strategy_fitness)))
        
        # Return the best one
        return max(tournament, key=lambda x: x[1])[0]
    
    def _crossover(self, parent1: Dict, parent2: Dict) -> Dict:
        """
        Create a new strategy by combining two parent strategies
        
        Args:
            parent1: First parent strategy
            parent2: Second parent strategy
            
        Returns:
            dict: Child strategy
        """
        child = {}
        
        # Inherit vector from one parent
        if parent1['vector'] == parent2['vector']:
            child['vector'] = parent1['vector']
        else:
            # Different vectors, choose one
            child['vector'] = random.choice([parent1['vector'], parent2['vector']])
        
        # For mixed strategies, combine vectors
        if child['vector'] == 'mixed':
            # Get vectors from both parents
            vectors1 = parent1.get('vectors', [parent1['vector']])
            vectors2 = parent2.get('vectors', [parent2['vector']])
            
            # Combine and deduplicate
            combined_vectors = list(set(vectors1 + vectors2))
            
            # Select up to 2 vectors
            child['vectors'] = random.sample(combined_vectors, min(2, len(combined_vectors)))
        
        # Inherit count (randomly from either parent)
        child['count'] = random.choice([parent1.get('count', 5), parent2.get('count', 5)])
        
        # Inherit burst (randomly from either parent)
        child['burst'] = random.choice([parent1.get('burst', 1), parent2.get('burst', 1)])
        
        # Inherit interval (randomly from either parent)
        child['interval'] = random.choice([parent1.get('interval', 0.15), parent2.get('interval', 0.15)])
        
        # Inherit reason if needed
        if child['vector'] in ['deauth', 'disassoc', 'pmf_bypass']:
            child['reason'] = random.choice([parent1.get('reason', 7), parent2.get('reason', 7)])
        
        # Inherit category if present in both parents
        if 'category' in parent1 and 'category' in parent2 and parent1['category'] == parent2['category']:
            child['category'] = parent1['category']
        
        return child
    
    def _mutate(self, strategy: Dict) -> Dict:
        """
        Mutate a strategy
        
        Args:
            strategy: Strategy to mutate
            
        Returns:
            dict: Mutated strategy
        """
        # Create a copy
        mutated = strategy.copy()
        
        # Select a random attribute to mutate
        attribute = random.choice(['vector', 'count', 'reason', 'burst', 'interval'])
        
        if attribute == 'vector':
            # Change vector
            available_vectors = [v.lower() for v in ATTACK_VECTORS.keys() if v.lower() != strategy['vector']]
            mutated['vector'] = random.choice(available_vectors)
            
            # Add reason if needed
            if mutated['vector'] in ['deauth', 'disassoc', 'pmf_bypass'] and 'reason' not in mutated:
                mutated['reason'] = random.choice(list(DEAUTH_REASON_CODES.keys()))
            # Remove reason if not needed
            elif mutated['vector'] not in ['deauth', 'disassoc', 'pmf_bypass'] and 'reason' in mutated:
                del mutated['reason']
        
        elif attribute == 'count':
            # Change packet count
            delta = random.choice([-4, -2, 2, 4])
            mutated['count'] = max(1, mutated.get('count', 5) + delta)
        
        elif attribute == 'reason' and strategy['vector'] in ['deauth', 'disassoc', 'pmf_bypass']:
            # Change reason code
            available_reasons = [r for r in DEAUTH_REASON_CODES.keys() if r != strategy.get('reason', 7)]
            mutated['reason'] = random.choice(available_reasons)
        
        elif attribute == 'burst':
            # Change burst count
            delta = random.choice([-1, 1])
            mutated['burst'] = max(1, min(5, mutated.get('burst', 1) + delta))
        
        elif attribute == 'interval':
            # Change interval
            options = [0.05, 0.1, 0.15, 0.2, 0.25]
            current = mutated.get('interval', 0.15)
            # Find closest option
            current_idx = min(range(len(options)), key=lambda i: abs(options[i] - current))
            # Select new option (prefer adjacent)
            new_idx = max(0, min(len(options) - 1, current_idx + random.choice([-1, 1])))
            mutated['interval'] = options[new_idx]
        
        return mutated
    
    def _create_mutated_strategy(self) -> Dict:
        """
        Create a new strategy through mutation
        
        Returns:
            dict: New strategy
        """
        # Start with a random strategy from population
        base_strategy = random.choice(self.population)
        
        # Apply multiple mutations
        mutated = base_strategy.copy()
        for _ in range(random.randint(1, 3)):
            mutated = self._mutate(mutated)
        
        return mutated
    
    def optimize_strategy(self, client_mac: str, device_category: str = None, 
                        target_reward: float = 0.8, max_iterations: int = 10) -> Dict:
        """
        Optimize a strategy for a specific client
        
        Args:
            client_mac: Client MAC address
            device_category: Device category
            target_reward: Target reward value
            max_iterations: Maximum optimization iterations
            
        Returns:
            dict: Optimized strategy
        """
        logger.debug(f"Optimizing strategy for client {client_mac}")
        
        # Start with the best known strategy
        best_strategy = self._select_exploitation_strategy(client_mac, device_category)
        best_hash = self._hash_strategy(best_strategy)
        
        # Get performance of best strategy
        if best_hash in self.strategy_performance:
            best_metrics = self.strategy_performance[best_hash]
            best_reward = best_metrics.get('avg_reward', 0.0)
        else:
            best_reward = 0.0
        
        # Return if already meeting target
        if best_reward >= target_reward:
            return best_strategy
        
        # Try to improve through local search
        for _ in range(max_iterations):
            # Create candidate by mutating best strategy
            candidate = self._mutate(best_strategy)
            candidate_hash = self._hash_strategy(candidate)
            
            # Evaluate candidate if we have data
            if candidate_hash in self.strategy_performance:
                candidate_metrics = self.strategy_performance[candidate_hash]
                candidate_reward = candidate_metrics.get('avg_reward', 0.0)
                
                # Update best if better
                if candidate_reward > best_reward:
                    best_strategy = candidate
                    best_reward = candidate_reward
                    
                    # Return if meeting target
                    if best_reward >= target_reward:
                        return best_strategy
        
        # Return best found strategy
        return best_strategy
    
    def get_strategy_stats(self) -> Dict:
        """
        Get statistics on strategy performance
        
        Returns:
            dict: Strategy statistics
        """
        stats = {
            'calls': self.calls,
            'successful_attacks': self.successful_attacks,
            'failed_attacks': self.failed_attacks,
            'success_rate': 0.0,
            'top_strategies': [],
            'category_strategies': {},
            'vector_performance': {}
        }
        
        # Calculate overall success rate
        total_attacks = self.successful_attacks + self.failed_attacks
        if total_attacks > 0:
            stats['success_rate'] = self.successful_attacks / total_attacks
        
        # Get top strategies
        top_strategies = []
        for strategy in self.population:
            strategy_hash = self._hash_strategy(strategy)
            
            if strategy_hash in self.strategy_performance:
                metrics = self.strategy_performance[strategy_hash]
                
                if metrics['attempts'] >= 3:  # Only consider strategies with enough attempts
                    top_strategies.append({
                        'strategy': strategy,
                        'success_rate': metrics['success_rate'],
                        'avg_reward': metrics['avg_reward'],
                        'attempts': metrics['attempts']
                    })
        
        # Sort by success rate
        top_strategies.sort(key=lambda x: x['success_rate'], reverse=True)
        
        # Keep top 5
        stats['top_strategies'] = top_strategies[:5]
        
        # Get category strategies
        for category, strategies in self.device_strategies.items():
            category_stats = []
            
            for strategy in strategies:
                strategy_hash = self._hash_strategy(strategy)
                
                if strategy_hash in self.strategy_performance:
                    metrics = self.strategy_performance[strategy_hash]
                    
                    if metrics['attempts'] > 0:
                        category_stats.append({
                            'strategy': strategy,
                            'success_rate': metrics['success_rate'],
                            'avg_reward': metrics['avg_reward'],
                            'attempts': metrics['attempts']
                        })
            
            # Sort by success rate
            category_stats.sort(key=lambda x: x['success_rate'], reverse=True)
            
            # Keep top 3
            stats['category_strategies'][category] = category_stats[:3]
        
        # Get vector performance
        vector_attacks = {}
        vector_successes = {}
        
        for strategy in self.population:
            strategy_hash = self._hash_strategy(strategy)
            vector = strategy['vector']
            
            if strategy_hash in self.strategy_performance:
                metrics = self.strategy_performance[strategy_hash]
                
                if vector not in vector_attacks:
                    vector_attacks[vector] = 0
                    vector_successes[vector] = 0
                
                vector_attacks[vector] += metrics['attempts']
                vector_successes[vector] += metrics['successes']
        
        # Calculate success rates
        for vector in vector_attacks:
            if vector_attacks[vector] > 0:
                stats['vector_performance'][vector] = vector_successes[vector] / vector_attacks[vector]
            else:
                stats['vector_performance'][vector] = 0.0
        
        return stats
    
    def get_client_strategy(self, client_mac: str) -> Dict:
        """
        Get optimal strategy for a specific client
        
        Args:
            client_mac: Client MAC address
            
        Returns:
            dict: Optimal strategy
        """
        # Check if we have history for this client
        if client_mac in self.client_results and len(self.client_results[client_mac]) > 0:
            # Analyze client history
            strategy_results = {}
            
            for strategy_hash, success in self.client_results[client_mac]:
                if strategy_hash not in strategy_results:
                    strategy_results[strategy_hash] = {'attempts': 0, 'successes': 0}
                
                strategy_results[strategy_hash]['attempts'] += 1
                if success:
                    strategy_results[strategy_hash]['successes'] += 1
            
            # Calculate success rates
            for s_hash in strategy_results:
                attempts = strategy_results[s_hash]['attempts']
                successes = strategy_results[s_hash]['successes']
                strategy_results[s_hash]['success_rate'] = successes / attempts if attempts > 0 else 0
            
            # Find best strategy
            best_hash = None
            best_rate = -1
            
            for s_hash, metrics in strategy_results.items():
                if metrics['attempts'] >= 3 and metrics['success_rate'] > best_rate:
                    best_hash = s_hash
                    best_rate = metrics['success_rate']
            
            # Return best strategy if found
            if best_hash:
                for strategy in self.population:
                    if self._hash_strategy(strategy) == best_hash:
                        return strategy
        
        # Fallback to best general strategy
        return self._select_exploitation_strategy(client_mac)
    
    def save_state(self, path: str = None) -> bool:
        """
        Save optimizer state to file
        
        Args:
            path: File path (default: None, uses default path)
            
        Returns:
            bool: True if saved successfully, False otherwise
        """
        if not path:
            # Use default path
            if not hasattr(self, 'save_dir'):
                self.save_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'models')
                
                # Create directory if it doesn't exist
                if not os.path.exists(self.save_dir):
                    try:
                        os.makedirs(self.save_dir)
                    except Exception as e:
                        logger.warning(f"Could not create save directory: {e}")
                        return False
            
            path = os.path.join(self.save_dir, 'strategy_optimizer.json')
        
        try:
            import json
            
            # Prepare data for serialization
            state = {
                'population': self.population,
                'strategy_performance': self.strategy_performance,
                'device_strategies': self.device_strategies,
                'client_results': self.client_results,
                'calls': self.calls,
                'successful_attacks': self.successful_attacks,
                'failed_attacks': self.failed_attacks,
                'exploration_rate': self.exploration_rate,
                'learning_rate': self.learning_rate,
                'discount_factor': self.discount_factor,
                'timestamp': time.time()
            }
            
            # Save to file
            with open(path, 'w') as f:
                json.dump(state, f, indent=2)
            
            logger.info(f"Saved optimizer state to {path}")
            return True
        except Exception as e:
            logger.error(f"Error saving optimizer state: {e}")
            return False
    
    def load_state(self, path: str = None) -> bool:
        """
        Load optimizer state from file
        
        Args:
            path: File path (default: None, uses default path)
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        if not path:
            # Use default path
            if not hasattr(self, 'save_dir'):
                self.save_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'models')
            
            path = os.path.join(self.save_dir, 'strategy_optimizer.json')
        
        try:
            import json
            
            # Check if file exists
            if not os.path.exists(path):
                logger.warning(f"State file not found: {path}")
                return False
            
            # Load from file
            with open(path, 'r') as f:
                state = json.load(f)
            
            # Restore state
            self.population = state.get('population', self.population)
            self.strategy_performance = state.get('strategy_performance', self.strategy_performance)
            self.device_strategies = state.get('device_strategies', self.device_strategies)
            self.client_results = state.get('client_results', self.client_results)
            self.calls = state.get('calls', self.calls)
            self.successful_attacks = state.get('successful_attacks', self.successful_attacks)
            self.failed_attacks = state.get('failed_attacks', self.failed_attacks)
            self.exploration_rate = state.get('exploration_rate', self.exploration_rate)
            self.learning_rate = state.get('learning_rate', self.learning_rate)
            self.discount_factor = state.get('discount_factor', self.discount_factor)
            
            logger.info(f"Loaded optimizer state from {path}")
            return True
        except Exception as e:
            logger.error(f"Error loading optimizer state: {e}")
            return False