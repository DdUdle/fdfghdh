"""
Test suite for the Wireless Network Analysis Framework.
"""

import os
import sys
import unittest

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def run_all_tests():
    """Run all tests in the test suite"""
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir)
    
    runner = unittest.TextTestRunner()
    return runner.run(suite)

def run_module_tests(module_name):
    """
    Run tests for a specific module
    
    Args:
        module_name: Name of the module to test (e.g., 'packet_crafter')
    
    Returns:
        unittest.TestResult: Test results
    """
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    
    # Look for test files matching the module name
    pattern = f'test_{module_name}.py'
    suite = loader.discover(start_dir, pattern=pattern)
    
    runner = unittest.TextTestRunner()
    return runner.run(suite)

if __name__ == '__main__':
    run_all_tests() 