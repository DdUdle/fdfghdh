"""
Wireless Network Analysis Framework - Command Line Argument Parser

This module provides command line argument parsing for the framework,
supporting various operational modes and configuration options.
"""

import os
import sys
import argparse
import logging
from typing import List

def parse_arguments(args: List[str] = None) -> argparse.Namespace:
    """
    Parse command line arguments
    
    Args:
        args: Command line arguments (default: sys.argv[1:])
        
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Advanced Wireless Network Analysis Framework',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Basic options
    parser.add_argument('-i', '--interfaces', nargs='+', 
                      help='Wireless interfaces to use')
    parser.add_argument('-c', '--config', 
                      help='Path to configuration file')
    parser.add_argument('-o', '--output-dir', 
                      help='Output directory for logs and data')
    parser.add_argument('-l', '--log-level', 
                      choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      default='INFO',
                      help='Logging level')
    
    # Operation modes
    mode_group = parser.add_argument_group('Operation modes')
    mode_group.add_argument('--monitor', action='store_true',
                          help='Monitor mode - passively monitor wireless traffic')
    mode_group.add_argument('--analyze', action='store_true',
                          help='Analysis mode - analyze wireless traffic and device behavior')
    mode_group.add_argument('--interactive', action='store_true',
                          help='Interactive mode - run with interactive shell')
    mode_group.add_argument('--daemon', action='store_true',
                          help='Daemon mode - run as a background service')
    
    # Target specification
    target_group = parser.add_argument_group('Target specification')
    target_group.add_argument('--ap', nargs='+', 
                            help='Target access point BSSID(s)')
    target_group.add_argument('--ssid', nargs='+', 
                            help='Target access point SSID(s)')
    target_group.add_argument('--channels', nargs='+', type=int, 
                            help='Channels to scan/monitor')
    target_group.add_argument('--clients', nargs='+', 
                            help='Target client MAC address(es)')
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced options')
    advanced_group.add_argument('--no-ai', action='store_true',
                              help='Disable AI/ML components')
    advanced_group.add_argument('--aggressive', action='store_true',
                              help='Use aggressive mode (faster detection, more traffic)')
    advanced_group.add_argument('--stealth', action='store_true',
                              help='Use stealth mode (slower detection, less traffic)')
    advanced_group.add_argument('--evasion-level', type=int, choices=[0, 1, 2, 3, 4], default=2,
                              help='Evasion level (0=none, 4=maximum)')
    advanced_group.add_argument('--hop-interval', type=float, default=0.3,
                              help='Channel hop interval in seconds')
    advanced_group.add_argument('--packet-count', type=int, default=5,
                              help='Number of packets per operation')
    advanced_group.add_argument('--region', choices=['US', 'EU', 'JP'], default='US',
                              help='Regulatory region for channel selection')
    
    # Output options
    output_group = parser.add_argument_group('Output options')
    output_group.add_argument('--json-output', action='store_true',
                            help='Output data in JSON format')
    output_group.add_argument('--csv-output', action='store_true',
                            help='Output data in CSV format')
    output_group.add_argument('--anonymize-mac', action='store_true',
                            help='Anonymize MAC addresses in output')
    output_group.add_argument('--quiet', action='store_true',
                            help='Suppress console output')
    output_group.add_argument('--verbose', action='store_true',
                            help='Verbose output (equivalent to --log-level DEBUG)')
    
    # Database options
    db_group = parser.add_argument_group('Database options')
    db_group.add_argument('--db-path', 
                         help='Path to device database')
    db_group.add_argument('--export-db', 
                         help='Export device database to file')
    db_group.add_argument('--import-db', 
                         help='Import device database from file')
    
    # Feature options
    feature_group = parser.add_argument_group('Feature options')
    feature_group.add_argument('--enable-fingerprinting', action='store_true',
                             help='Enable device fingerprinting')
    feature_group.add_argument('--enable-pattern-mining', action='store_true',
                             help='Enable temporal pattern mining')
    feature_group.add_argument('--enable-adaptive-strategy', action='store_true',
                             help='Enable adaptive strategy optimization')
    
    # Parse arguments
    if args is None:
        args = sys.argv[1:]
    
    parsed_args = parser.parse_args(args)
    
    # Post-process arguments
    if parsed_args.verbose:
        parsed_args.log_level = 'DEBUG'
    
    # Ensure at least one operation mode is specified
    if not any([parsed_args.monitor, parsed_args.analyze, parsed_args.interactive, parsed_args.daemon]):
        parsed_args.interactive = True
    
    # Ensure interfaces are provided if required modes are enabled
    if (parsed_args.monitor or parsed_args.analyze) and not parsed_args.interfaces:
        parser.error("--interfaces is required for monitor and analyze modes")
    
    return parsed_args