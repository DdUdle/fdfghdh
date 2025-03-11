"""
Wireless Network Analysis Framework - Configuration Manager

This module provides dynamic configuration handling with hierarchical inheritance,
environment variable integration, and runtime modifications.
"""

import os
import json
import logging
import copy
from typing import Dict, List, Optional, Union, Any

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

class ConfigManager:
    """
    Dynamic configuration manager with hierarchical inheritance,
    environment variable integration, and runtime modifications.
    """
    
    def __init__(self, config_path: str = None):
        """
        Initialize the configuration manager
        
        Args:
            config_path: Path to the configuration file (default: None)
        """
        # Default paths
        self.base_dir = os.path.join(os.path.dirname(__file__), '..', '..')
        self.default_config_path = os.path.join(self.base_dir, 'data', 'configs', 'default.json')
        
        # Configuration stores
        self.config = {}
        self.default_config = {}
        self.interface_configs = {}
        
        # Load default configuration
        self._load_default_config()
        
        # Load specified configuration if provided
        if config_path:
            self.load_config(config_path)
    
    def _load_default_config(self):
        """Load default configuration"""
        try:
            if os.path.exists(self.default_config_path):
                with open(self.default_config_path, 'r') as f:
                    self.default_config = json.load(f)
                logger.info(f"Loaded default configuration from {self.default_config_path}")
            else:
                logger.warning(f"Default configuration file not found: {self.default_config_path}")
                
                # Initialize with minimal default configuration
                self.default_config = {
                    "general": {
                        "log_level": "INFO",
                        "enable_ai": True,
                        "evasion_level": 2,
                        "channel_hop_interval": 0.3,
                        "client_timeout": 300,
                        "autosave_interval": 60
                    },
                    "attack": {
                        "packet_count": 5,
                        "deauth_rate": 0.1,
                        "min_attack_interval": 5.0,
                        "max_retries": 10,
                        "preferred_vectors": ["deauth", "disassoc"]
                    },
                    "ai": {
                        "learning_rate": 0.001,
                        "discount_factor": 0.95,
                        "exploration_rate": 0.2,
                        "mode": "balanced"
                    },
                    "interfaces": {
                        "default": {
                            "hop_channels": [1, 6, 11],
                            "region": "US"
                        }
                    }
                }
                
                # Create default config file
                self._save_default_config()
            
            # Copy default config to current config
            self.config = copy.deepcopy(self.default_config)
            
        except Exception as e:
            logger.error(f"Error loading default configuration: {e}")
            # Initialize with empty configuration
            self.default_config = {}
            self.config = {}
    
    def _save_default_config(self):
        """Save default configuration to file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.default_config_path), exist_ok=True)
            
            with open(self.default_config_path, 'w') as f:
                json.dump(self.default_config, f, indent=2)
            
            logger.info(f"Saved default configuration to {self.default_config_path}")
            
        except Exception as e:
            logger.error(f"Error saving default configuration: {e}")
    
    def load_config(self, config_path: str) -> bool:
        """
        Load configuration from a file
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        if not os.path.exists(config_path):
            logger.error(f"Configuration file not found: {config_path}")
            return False
        
        try:
            with open(config_path, 'r') as f:
                loaded_config = json.load(f)
            
            # Merge with default configuration
            self._merge_configs(self.config, loaded_config)
            
            # Extract interface-specific configurations
            if 'interfaces' in loaded_config:
                for interface, interface_config in loaded_config['interfaces'].items():
                    self.interface_configs[interface] = interface_config
            
            logger.info(f"Loaded configuration from {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def _merge_configs(self, base_config: Dict, override_config: Dict):
        """
        Recursively merge configurations
        
        Args:
            base_config: Base configuration to merge into
            override_config: Configuration that overrides base values
        """
        for key, value in override_config.items():
            if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
                self._merge_configs(base_config[key], value)
            else:
                base_config[key] = value
    
    def get_value(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value
        
        Args:
            key: Configuration key (dot-separated for nested keys)
            default: Default value if key not found
            
        Returns:
            Any: Configuration value or default if not found
        """
        # Check environment variable override
        env_key = f"WNET_{key.upper().replace('.', '_')}"
        env_value = os.environ.get(env_key)
        if env_value is not None:
            # Convert environment variable to appropriate type
            try:
                # Try to parse as JSON first (for lists, dicts, etc.)
                return json.loads(env_value)
            except:
                # If not valid JSON, return as string
                return env_value
        
        # Navigate nested dictionary
        parts = key.split('.')
        config = self.config
        
        for part in parts:
            if part in config:
                config = config[part]
            else:
                return default
        
        return config
    
    def set_value(self, key: str, value: Any) -> bool:
        """
        Set a configuration value
        
        Args:
            key: Configuration key (dot-separated for nested keys)
            value: Value to set
            
        Returns:
            bool: True if set successfully, False otherwise
        """
        try:
            # Navigate nested dictionary
            parts = key.split('.')
            config = self.config
            
            # Create nested dictionaries if they don't exist
            for i, part in enumerate(parts[:-1]):
                if part not in config:
                    config[part] = {}
                elif not isinstance(config[part], dict):
                    # Convert non-dict to dict (this will overwrite the value)
                    config[part] = {}
                
                config = config[part]
            
            # Set the value
            config[parts[-1]] = value
            return True
            
        except Exception as e:
            logger.error(f"Error setting configuration value: {e}")
            return False
    
    def get_interface_config(self, interface: str) -> Dict:
        """
        Get configuration for a specific interface
        
        Args:
            interface: Interface name
            
        Returns:
            dict: Interface configuration
        """
        # Check if we have a specific configuration for this interface
        if interface in self.interface_configs:
            # Start with default interface config
            if 'default' in self.interface_configs:
                interface_config = copy.deepcopy(self.interface_configs['default'])
            else:
                interface_config = {}
            
            # Override with interface-specific config
            self._merge_configs(interface_config, self.interface_configs[interface])
            
            return interface_config
        
        # Return default interface config if available
        elif 'default' in self.interface_configs:
            return copy.deepcopy(self.interface_configs['default'])
        
        # Return empty config
        else:
            return {}
    
    def set_interface_config(self, interface: str, config: Dict) -> bool:
        """
        Set configuration for a specific interface
        
        Args:
            interface: Interface name
            config: Interface configuration
            
        Returns:
            bool: True if set successfully, False otherwise
        """
        try:
            self.interface_configs[interface] = config
            
            # Update interfaces section in main config
            if 'interfaces' not in self.config:
                self.config['interfaces'] = {}
            
            self.config['interfaces'][interface] = config
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting interface configuration: {e}")
            return False
    
    def get_all(self) -> Dict:
        """
        Get the complete configuration
        
        Returns:
            dict: Complete configuration
        """
        return copy.deepcopy(self.config)
    
    def reset_to_defaults(self) -> bool:
        """
        Reset configuration to defaults
        
        Returns:
            bool: True if reset successfully, False otherwise
        """
        try:
            self.config = copy.deepcopy(self.default_config)
            self.interface_configs = {}
            
            # Extract interface-specific configurations
            if 'interfaces' in self.config:
                for interface, interface_config in self.config['interfaces'].items():
                    self.interface_configs[interface] = interface_config
            
            logger.info("Reset configuration to defaults")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting configuration: {e}")
            return False
    
    def save_config(self, config_path: str = None) -> bool:
        """
        Save configuration to a file
        
        Args:
            config_path: Path to save the configuration to (default: None)
            
        Returns:
            bool: True if saved successfully, False otherwise
        """
        if not config_path:
            # Use default path
            config_path = os.path.join(self.base_dir, 'data', 'configs', 'current.json')
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            logger.info(f"Saved configuration to {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get_with_prefix(self, prefix: str) -> Dict:
        """
        Get all configuration values with a specific prefix
        
        Args:
            prefix: Configuration key prefix
            
        Returns:
            dict: Configuration values with the prefix
        """
        result = {}
        prefix_parts = prefix.split('.')
        
        def extract_with_prefix(config, current_parts, remaining_parts, target):
            if not remaining_parts:
                # We've reached the prefix, copy everything at this level
                if isinstance(config, dict):
                    for key, value in config.items():
                        target[key] = copy.deepcopy(value)
                return
            
            # Navigate to the next level
            current_key = remaining_parts[0]
            if current_key in config and isinstance(config[current_key], dict):
                if current_key not in target:
                    target[current_key] = {}
                extract_with_prefix(
                    config[current_key],
                    current_parts + [current_key],
                    remaining_parts[1:],
                    target[current_key]
                )
        
        extract_with_prefix(self.config, [], prefix_parts, result)
        return result
    
    def load_from_dict(self, config_dict: Dict) -> bool:
        """
        Load configuration from a dictionary
        
        Args:
            config_dict: Configuration dictionary
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            # Reset to defaults first
            self.reset_to_defaults()
            
            # Merge with provided dictionary
            self._merge_configs(self.config, config_dict)
            
            # Extract interface-specific configurations
            if 'interfaces' in config_dict:
                for interface, interface_config in config_dict['interfaces'].items():
                    self.interface_configs[interface] = interface_config
            
            logger.info("Loaded configuration from dictionary")
            return True
            
        except Exception as e:
            logger.error(f"Error loading configuration from dictionary: {e}")
            return False
    
    def load_from_env(self, prefix: str = "WNET_") -> int:
        """
        Load configuration from environment variables
        
        Args:
            prefix: Environment variable prefix
            
        Returns:
            int: Number of configuration values loaded
        """
        count = 0
        
        try:
            for env_key, env_value in os.environ.items():
                if env_key.startswith(prefix):
                    # Convert environment key to config key
                    config_key = env_key[len(prefix):].lower().replace('_', '.')
                    
                    # Try to parse value as JSON
                    try:
                        value = json.loads(env_value)
                    except:
                        # If not valid JSON, use as string
                        value = env_value
                    
                    # Set the value
                    if self.set_value(config_key, value):
                        count += 1
            
            logger.info(f"Loaded {count} configuration values from environment variables")
            return count
            
        except Exception as e:
            logger.error(f"Error loading configuration from environment: {e}")
            return count