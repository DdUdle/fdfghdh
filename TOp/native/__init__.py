"""
Native C/C++ extensions for performance-critical operations
with graceful fallbacks to pure Python implementations.
"""

import os
import sys
import ctypes
from ..utils.logging import setup_logger

logger = setup_logger(__name__)

# Initialize state
NATIVE_LIBRARY_LOADED = False
NATIVE_LIBRARY_PATH = None
NATIVE_FUNCTIONS_AVAILABLE = {}

def _find_native_library():
    """Find the native library in common locations"""
    # Possible locations for the native library
    search_paths = [
        os.path.join(os.path.dirname(__file__), 'libpacket.so'),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 'native', 'libpacket.so'),
        '/usr/local/lib/libpacket.so',
        '/usr/lib/libpacket.so',
        'libpacket.so'
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            return path
    
    return None

def initialize_native_library():
    """Initialize the native library if available"""
    global NATIVE_LIBRARY_LOADED, NATIVE_LIBRARY_PATH, NATIVE_FUNCTIONS_AVAILABLE
    
    if NATIVE_LIBRARY_LOADED:
        return True
    
    try:
        native_lib_path = _find_native_library()
        if not native_lib_path:
            logger.info("Native packet library not found, using pure Python implementation")
            return False
        
        logger.info(f"Loading native packet library from {native_lib_path}")
        native_lib = ctypes.CDLL(native_lib_path)
        
        # Initialize the library
        if hasattr(native_lib, 'initialize'):
            native_lib.initialize()
        
        # Register available functions
        function_names = [
            'send_deauth',
            'send_disassoc',
            'send_null_func',
            'send_auth_flood',
            'set_channel',
            'scan_channels',
            'start_channel_hopper',
            'stop_channel_hopper'
        ]
        
        for func_name in function_names:
            if hasattr(native_lib, func_name):
                NATIVE_FUNCTIONS_AVAILABLE[func_name] = True
            else:
                NATIVE_FUNCTIONS_AVAILABLE[func_name] = False
        
        # Save library state
        NATIVE_LIBRARY_LOADED = True
        NATIVE_LIBRARY_PATH = native_lib_path
        
        return True
    except Exception as e:
        logger.warning(f"Failed to load native packet library: {e}")
        return False

def get_native_library_status():
    """Get the status of the native library"""
    return {
        'loaded': NATIVE_LIBRARY_LOADED,
        'path': NATIVE_LIBRARY_PATH,
        'functions': NATIVE_FUNCTIONS_AVAILABLE
    }

# Attempt to initialize on import
initialize_native_library() 