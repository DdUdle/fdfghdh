"""
Core engine components for the Wireless Network Analysis Framework.
"""

# Export key components
from .engine import Engine as AnalysisEngine
from .config import ConfigManager
from .constants import (
    DEFAULT_TIMEOUT, DEFAULT_INTERVAL, CLIENT_TIMEOUT,
    DEFAULT_DEAUTH_RATE, DEFAULT_PACKET_COUNT,
    ATTACK_VECTORS, DEAUTH_REASON_CODES
)

# Initialize engine settings
INITIALIZED = False
DEFAULT_CONFIG_LOADED = False

def initialize_core():
    """Initialize core components"""
    global INITIALIZED
    
    if not INITIALIZED:
        from .config import load_default_config
        load_default_config()
        INITIALIZED = True
    
    return INITIALIZED

__all__ = [
    'AnalysisEngine',
    'ConfigManager',
    'DEFAULT_TIMEOUT',
    'DEFAULT_INTERVAL',
    'CLIENT_TIMEOUT',
    'DEFAULT_DEAUTH_RATE',
    'DEFAULT_PACKET_COUNT',
    'ATTACK_VECTORS',
    'DEAUTH_REASON_CODES',
    'initialize_core'
] 