"""
Data resources for the Wireless Network Analysis Framework.
"""

import os
import json

# Data directory paths
DATA_DIR = os.path.dirname(__file__)
VENDOR_DB_PATH = os.path.join(DATA_DIR, 'vendor_db.json')
CONFIGS_DIR = os.path.join(DATA_DIR, 'configs')
MODELS_DIR = os.path.join(DATA_DIR, 'models')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')

def load_vendor_database():
    """Load vendor database from file"""
    if not os.path.exists(VENDOR_DB_PATH):
        return {}
    
    try:
        with open(VENDOR_DB_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        from ..utils.logging import setup_logger
        logger = setup_logger(__name__)
        logger.error(f"Error loading vendor database: {e}")
        return {}

def get_default_config_path():
    """Get path to default configuration file"""
    default_config = os.path.join(CONFIGS_DIR, 'default.json')
    if os.path.exists(default_config):
        return default_config
    
    # Create directories if they don't exist
    if not os.path.exists(CONFIGS_DIR):
        os.makedirs(CONFIGS_DIR, exist_ok=True)
    
    if not os.path.exists(MODELS_DIR):
        os.makedirs(MODELS_DIR, exist_ok=True)
    
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR, exist_ok=True)
    
    return default_config

def ensure_data_directories():
    """Ensure all data directories exist"""
    os.makedirs(CONFIGS_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    return {
        'data_dir': os.path.abspath(DATA_DIR),
        'configs_dir': os.path.abspath(CONFIGS_DIR),
        'models_dir': os.path.abspath(MODELS_DIR),
        'logs_dir': os.path.abspath(LOGS_DIR)
    } 