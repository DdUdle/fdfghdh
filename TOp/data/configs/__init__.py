"""
Configuration file management for the Wireless Network Analysis Framework.
"""

import os
import json

def list_available_configs():
    """List available configuration files"""
    config_dir = os.path.dirname(__file__)
    config_files = [f for f in os.listdir(config_dir) if f.endswith('.json')]
    return config_files

def load_config(config_name):
    """
    Load a configuration file by name
    
    Args:
        config_name: Name of the configuration file (without path)
        
    Returns:
        dict: Configuration data or empty dict if not found
    """
    config_path = os.path.join(os.path.dirname(__file__), config_name)
    if not os.path.exists(config_path):
        return {}
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        from ...utils.logging import setup_logger
        logger = setup_logger(__name__)
        logger.error(f"Error loading configuration file {config_name}: {e}")
        return {}

def create_default_config():
    """Create default configuration file if it doesn't exist"""
    default_path = os.path.join(os.path.dirname(__file__), 'default.json')
    
    if os.path.exists(default_path):
        return default_path
    
    # Default configuration
    default_config = {
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
    
    try:
        with open(default_path, 'w') as f:
            json.dump(default_config, f, indent=2)
        return default_path
    except Exception as e:
        from ...utils.logging import setup_logger
        logger = setup_logger(__name__)
        logger.error(f"Error creating default configuration file: {e}")
        return None 