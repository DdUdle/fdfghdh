#!/usr/bin/env python3
"""
Wireless Network Analysis Framework - Main Entry Point

This module serves as the main entry point for the framework, coordinating
all components and providing the command-line interface.
"""

import os
import sys
import time
import signal
import logging
from typing import Dict, List, Optional, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import framework components
from framework.core.engine import AnalysisEngine
from framework.core.config import ConfigManager
from framework.cli.argparser import parse_arguments
from framework.cli.interactive import InteractiveShell
from framework.utils.logging import setup_enhanced_logging, setup_logger

# Global variables
engine = None
config_manager = None
logger = None

def setup_signal_handlers():
    """Set up signal handlers for graceful shutdown"""
    def signal_handler(sig, frame):
        """Handle signals for graceful shutdown"""
        logger.info(f"Received signal {sig}, shutting down...")
        if engine and engine.running:
            engine.stop()
        sys.exit(0)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def start_interactive_shell(engine_instance: AnalysisEngine):
    """
    Start the interactive shell
    
    Args:
        engine_instance: AnalysisEngine instance
    """
    shell = InteractiveShell(engine_instance)
    shell.cmdloop()

def daemon_mode(engine_instance: AnalysisEngine):
    """
    Run in daemon mode
    
    Args:
        engine_instance: AnalysisEngine instance
    """
    # Detach from terminal
    if os.fork() > 0:
        sys.exit(0)
    
    os.setsid()
    
    if os.fork() > 0:
        sys.exit(0)
    
    # Close standard file descriptors
    sys.stdin.close()
    sys.stdout.close()
    sys.stderr.close()
    
    # Run in background
    logger.info("Running in daemon mode")
    
    while engine_instance.running:
        time.sleep(1)

def main():
    """Main function"""
    global engine, config_manager, logger
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up logging
    log_dir = args.output_dir
    log_level = getattr(logging, args.log_level.upper())
    logging_system = setup_enhanced_logging(log_dir, log_level, args.anonymize_mac)
    logger = setup_logger("main", log_level)
    
    if args.quiet:
        # Suppress console output
        console_handler = next((h for h in logging.getLogger().handlers if isinstance(h, logging.StreamHandler)), None)
        if console_handler:
            logging.getLogger().removeHandler(console_handler)
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    
    # Override config with command line arguments
    if args.interfaces:
        config_manager.set_value('interfaces', args.interfaces)
    
    if args.no_ai:
        config_manager.set_value('general.enable_ai', False)
    
    if args.aggressive:
        config_manager.set_value('general.mode', 'aggressive')
    elif args.stealth:
        config_manager.set_value('general.mode', 'stealth')
    
    if args.evasion_level is not None:
        config_manager.set_value('general.evasion_level', args.evasion_level)
    
    if args.hop_interval:
        config_manager.set_value('general.channel_hop_interval', args.hop_interval)
    
    if args.packet_count:
        config_manager.set_value('attack.packet_count', args.packet_count)
    
    if args.region:
        config_manager.set_value('general.region', args.region)
    
    # Initialize engine with configuration
    interfaces = config_manager.get_value('interfaces', [])
    config = config_manager.get_all()
    
    logger.info(f"Initializing engine with interfaces: {interfaces}")
    engine = AnalysisEngine(interfaces, config)
    
    # Set up signal handlers
    setup_signal_handlers()
    
    # Initialize engine
    if not engine.initialize():
        logger.error("Failed to initialize engine")
        return 1
    
    # Process target specifications
    if args.ap:
        for ap in args.ap:
            # Format: BSSID:ESSID:CHANNEL
            parts = ap.split(':')
            if len(parts) >= 3:
                bssid = parts[0]
                essid = parts[1]
                channel = int(parts[2])
                engine.add_target_ap(bssid, essid, channel)
    
    if args.channels:
        # Override preferred channels in channel hopper
        if hasattr(engine, 'channel_hopper') and engine.channel_hopper:
            engine.channel_hopper.preferred_channels = args.channels
    
    # Start engine if needed
    if args.monitor or args.analyze:
        logger.info("Starting engine")
        if not engine.start():
            logger.error("Failed to start engine")
            return 1
    
    # Run in selected mode
    try:
        if args.interactive:
            # Interactive mode
            logger.info("Starting interactive shell")
            start_interactive_shell(engine)
        elif args.daemon:
            # Daemon mode
            logger.info("Starting daemon mode")
            daemon_mode(engine)
        else:
            # Run in background
            logger.info("Running in background mode")
            while engine.running:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt, stopping...")
    except Exception as e:
        logger.error(f"Error in main loop: {e}", exc_info=True)
    finally:
        # Stop engine
        if engine.running:
            logger.info("Stopping engine")
            engine.stop()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())