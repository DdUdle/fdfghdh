"""
Advanced Wireless Network Analysis Framework

A sophisticated framework for security-focused wireless network analysis,
with advanced behavioral modeling and protocol inspection capabilities.
"""

__version__ = '0.1.0'
__author__ = 'Security Research Team'

# Framework constants
FRAMEWORK_NAME = "Wireless Network Analysis Framework"
FRAMEWORK_CODENAME = "SpectrumObserver"

# Initialize logging early
from .utils.logging import setup_logger
logger = setup_logger(__name__)

# Export core classes for direct import
from .core.engine import Engine as AnalysisEngine
from .core.config import ConfigManager

# Module availability flags - determined at runtime
from .modules import PACKET_CRAFTING_AVAILABLE, MONITOR_MODE_AVAILABLE
from .ai import ML_CAPABILITIES_AVAILABLE, TORCH_AVAILABLE

def system_check():
    """Perform system compatibility check"""
    from .utils.helpers import check_dependencies, is_root
    
    results = {
        'root': is_root(),
        'dependencies': check_dependencies(),
        'packet_crafting': PACKET_CRAFTING_AVAILABLE,
        'monitor_mode': MONITOR_MODE_AVAILABLE,
        'ml_capabilities': ML_CAPABILITIES_AVAILABLE
    }
    return results 