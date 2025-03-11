"""
Wireless Network Analysis Framework - Enhanced Logging Module

This module provides advanced logging capabilities with multi-format output,
flexible filtering, and specialized logging for different analysis operations.
"""

import os
import json
import time
import logging
import logging.handlers
import datetime
from typing import Dict, List, Optional, Union, Any
import hashlib

# Custom log levels
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

class MacAnonymizer:
    """Handles MAC address anonymization for privacy-preserving logging"""
    
    def __init__(self, salt: str = None, persistent: bool = True):
        """
        Initialize the MAC anonymizer
        
        Args:
            salt: Salt for hashing (default: random)
            persistent: Whether to use persistent mappings (default: True)
        """
        self.salt = salt or str(time.time())
        self.persistent = persistent
        self.mac_map = {}
        self.mapping_file = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'mac_map.json')
        
        # Load existing mappings if persistent
        if persistent:
            self._load_mappings()
    
    def anonymize(self, mac_address: str) -> str:
        """
        Anonymize a MAC address
        
        Args:
            mac_address: MAC address to anonymize
            
        Returns:
            str: Anonymized MAC address
        """
        if not mac_address:
            return "00:00:00:00:00:00"
        
        # Normalize MAC address
        mac = mac_address.lower().replace('-', ':')
        
        # Check if we already have a mapping
        if mac in self.mac_map:
            return self.mac_map[mac]
        
        # Create a new mapping
        mac_hash = hashlib.sha256((mac + self.salt).encode()).hexdigest()
        
        # Format like a MAC address for readability
        anon_mac = ':'.join([mac_hash[i:i+2] for i in range(0, 12, 2)])
        
        # Store the mapping
        self.mac_map[mac] = anon_mac
        
        # Save if persistent
        if self.persistent and len(self.mac_map) % 10 == 0:
            self._save_mappings()
        
        return anon_mac
    
    def deanonymize(self, anon_mac: str) -> Optional[str]:
        """
        Deanonymize a MAC address if mapping exists
        
        Args:
            anon_mac: Anonymized MAC address
            
        Returns:
            str: Original MAC address or None if not found
        """
        # Check for reverse mapping
        for original, anonymized in self.mac_map.items():
            if anonymized == anon_mac:
                return original
        
        return None
    
    def _load_mappings(self):
        """Load MAC mappings from file"""
        try:
            if os.path.exists(self.mapping_file):
                with open(self.mapping_file, 'r') as f:
                    self.mac_map = json.load(f)
        except Exception as e:
            pass
    
    def _save_mappings(self):
        """Save MAC mappings to file"""
        try:
            os.makedirs(os.path.dirname(self.mapping_file), exist_ok=True)
            with open(self.mapping_file, 'w') as f:
                json.dump(self.mac_map, f)
        except Exception as e:
            pass

class EnhancedLogger(logging.Logger):
    """Enhanced logger with additional methods for specialized logging"""
    
    def trace(self, msg, *args, **kwargs):
        """Log at TRACE level"""
        self.log(TRACE, msg, *args, **kwargs)

class EnhancedLogging:
    """
    Advanced logging system with multiple output formats, severity filtering,
    and specialized logging for different analysis operations.
    """
    
    def __init__(self, log_dir: str = None, log_level: int = logging.INFO, anonymize: bool = True):
        """
        Initialize the enhanced logging system
        
        Args:
            log_dir: Directory for log files (default: data/logs)
            log_level: Minimum log level (default: INFO)
            anonymize: Whether to anonymize MAC addresses (default: True)
        """
        # Set up log directory
        self.log_dir = log_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'logs')
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Set up log level
        self.log_level = log_level
        
        # Initialize MAC anonymizer if enabled
        self.anonymize = anonymize
        if anonymize:
            self.mac_anonymizer = MacAnonymizer()
        
        # Set up log files
        self.main_log = os.path.join(self.log_dir, 'main.log')
        self.attack_log = os.path.join(self.log_dir, 'attacks.log')
        self.event_log = os.path.join(self.log_dir, 'events.log')
        self.error_log = os.path.join(self.log_dir, 'errors.log')
        
        # Statistics for performance logging
        self.stats = {
            'start_time': time.time(),
            'attack_events': 0,
            'detection_events': 0,
            'success_count': 0,
            'failure_count': 0,
            'error_count': 0
        }
        
        # Configure logging system
        self._configure_logging()
    
    def _configure_logging(self):
        """Configure the logging system"""
        # Register custom logger class
        logging.setLoggerClass(EnhancedLogger)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self.log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create console handler
        console = logging.StreamHandler()
        console.setLevel(self.log_level)
        console_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%H:%M:%S'
        )
        console.setFormatter(console_format)
        root_logger.addHandler(console)
        
        # Create file handler for main log
        main_handler = logging.handlers.RotatingFileHandler(
            self.main_log, maxBytes=10*1024*1024, backupCount=5
        )
        main_handler.setLevel(self.log_level)
        main_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        main_handler.setFormatter(main_format)
        root_logger.addHandler(main_handler)
        
        # Create file handler for error log
        error_handler = logging.handlers.RotatingFileHandler(
            self.error_log, maxBytes=5*1024*1024, backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        error_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s\n'
            'File: %(pathname)s:%(lineno)d\n',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        error_handler.setFormatter(error_format)
        root_logger.addHandler(error_handler)
    
    def setup_logger(self, name: str, level: int = None) -> logging.Logger:
        """
        Set up a logger for a specific module
        
        Args:
            name: Logger name
            level: Log level (default: self.log_level)
            
        Returns:
            logging.Logger: Configured logger
        """
        logger = logging.getLogger(name)
        logger.setLevel(level or self.log_level)
        return logger
    
    def log_attack_event(self, mac_address: str, vector: str, success: bool, 
                        interface: str = None, channel: int = None,
                        details: Dict = None):
        """
        Log an attack event
        
        Args:
            mac_address: Target MAC address
            vector: Attack vector used
            success: Whether the attack was successful
            interface: Interface used (optional)
            channel: Channel used (optional)
            details: Additional details (optional)
        """
        # Anonymize MAC if enabled
        if self.anonymize and hasattr(self, 'mac_anonymizer'):
            anon_mac = self.mac_anonymizer.anonymize(mac_address)
        else:
            anon_mac = mac_address
        
        # Prepare event data
        event = {
            'timestamp': time.time(),
            'formatted_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'mac_address': anon_mac,
            'vector': vector,
            'success': success,
            'interface': interface,
            'channel': channel
        }
        
        # Add additional details if provided
        if details:
            event.update(details)
        
        # Write to attack log
        try:
            with open(self.attack_log, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logging.error(f"Failed to write to attack log: {e}")
        
        # Update statistics
        self.stats['attack_events'] += 1
        if success:
            self.stats['success_count'] += 1
        else:
            self.stats['failure_count'] += 1
        
        # Log to main logger as well
        result = "successful" if success else "failed"
        msg = f"Attack event ({result}): vector={vector} target={anon_mac}"
        if interface:
            msg += f" interface={interface}"
        if channel:
            msg += f" channel={channel}"
        
        logging.info(msg)
    
    def log_detection_event(self, event_type: str, details: Dict):
        """
        Log a detection event
        
        Args:
            event_type: Type of detection event
            details: Event details
        """
        # Anonymize MAC addresses in details if enabled
        if self.anonymize and hasattr(self, 'mac_anonymizer'):
            anonymized_details = {}
            for key, value in details.items():
                if key.endswith('_mac') or key in ['mac_address', 'client', 'bssid']:
                    anonymized_details[key] = self.mac_anonymizer.anonymize(value)
                else:
                    anonymized_details[key] = value
        else:
            anonymized_details = details
        
        # Prepare event data
        event = {
            'timestamp': time.time(),
            'formatted_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': event_type,
            'details': anonymized_details
        }
        
        # Write to event log
        try:
            with open(self.event_log, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logging.error(f"Failed to write to event log: {e}")
        
        # Update statistics
        self.stats['detection_events'] += 1
        
        # Log to main logger as well
        msg = f"Detection event: {event_type}"
        if 'mac_address' in anonymized_details:
            msg += f" target={anonymized_details['mac_address']}"
        elif 'client' in anonymized_details:
            msg += f" target={anonymized_details['client']}"
        
        logging.info(msg)
    
    def log_performance_summary(self) -> Dict:
        """
        Log performance summary
        
        Returns:
            dict: Performance statistics
        """
        # Calculate runtime
        current_time = time.time()
        runtime = current_time - self.stats['start_time']
        
        # Calculate success rate
        total_attacks = self.stats['success_count'] + self.stats['failure_count']
        success_rate = self.stats['success_count'] / max(1, total_attacks)
        
        # Prepare summary
        summary = {
            'timestamp': current_time,
            'formatted_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'runtime_seconds': runtime,
            'runtime_formatted': str(datetime.timedelta(seconds=int(runtime))),
            'attack_events': self.stats['attack_events'],
            'detection_events': self.stats['detection_events'],
            'success_count': self.stats['success_count'],
            'failure_count': self.stats['failure_count'],
            'error_count': self.stats['error_count'],
            'success_rate': success_rate,
            'events_per_minute': (self.stats['attack_events'] + self.stats['detection_events']) / (runtime / 60)
        }
        
        # Log to main logger
        logging.info(f"Performance summary: runtime={summary['runtime_formatted']}, "
                    f"events={summary['attack_events'] + summary['detection_events']}, "
                    f"success_rate={success_rate:.2f}")
        
        return summary
    
    def rotate_logs(self) -> bool:
        """
        Rotate log files
        
        Returns:
            bool: True if rotated successfully, False otherwise
        """
        try:
            # Get current timestamp for archive names
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            
            # Rotate main log
            if os.path.exists(self.main_log):
                archive_path = f"{self.main_log}.{timestamp}"
                os.rename(self.main_log, archive_path)
            
            # Rotate attack log
            if os.path.exists(self.attack_log):
                archive_path = f"{self.attack_log}.{timestamp}"
                os.rename(self.attack_log, archive_path)
            
            # Rotate event log
            if os.path.exists(self.event_log):
                archive_path = f"{self.event_log}.{timestamp}"
                os.rename(self.event_log, archive_path)
            
            # Rotate error log
            if os.path.exists(self.error_log):
                archive_path = f"{self.error_log}.{timestamp}"
                os.rename(self.error_log, archive_path)
            
            # Reconfigure logging to use new files
            self._configure_logging()
            
            logging.info(f"Logs rotated at {timestamp}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to rotate logs: {e}")
            return False

# Singleton instance for global access
_enhanced_logging = None

def setup_enhanced_logging(log_dir: str = None, log_level: int = logging.INFO, anonymize: bool = True) -> EnhancedLogging:
    """
    Set up the enhanced logging system
    
    Args:
        log_dir: Directory for log files
        log_level: Minimum log level
        anonymize: Whether to anonymize MAC addresses
        
    Returns:
        EnhancedLogging: The logging system instance
    """
    global _enhanced_logging
    if _enhanced_logging is None:
        _enhanced_logging = EnhancedLogging(log_dir, log_level, anonymize)
    return _enhanced_logging

def setup_logger(name: str, level: int = None) -> logging.Logger:
    """
    Set up a logger for a specific module
    
    Args:
        name: Logger name
        level: Log level (default: INFO)
        
    Returns:
        logging.Logger: Configured logger
    """
    # Initialize enhanced logging if not already
    global _enhanced_logging
    if _enhanced_logging is None:
        _enhanced_logging = EnhancedLogging()
    
    # Get logger from enhanced logging
    return _enhanced_logging.setup_logger(name, level)