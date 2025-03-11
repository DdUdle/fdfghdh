"""
Wireless Network Analysis Framework - Interactive Shell

This module provides an interactive command-line interface for controlling
the framework, managing operations, and viewing results in real-time.
"""

import os
import sys
import cmd
import time
import json
import shlex
import threading
import logging
from typing import Dict, List, Optional, Any

# Import engine for type hints
from ..core.engine import AnalysisEngine

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

class InteractiveShell(cmd.Cmd):
    """
    Interactive command-line interface for framework control
    """
    
    intro = """
╔════════════════════════════════════════════════════╗
║     Wireless Network Analysis Framework Shell      ║
║      Type 'help' or '?' for available commands     ║
╚════════════════════════════════════════════════════╝
"""
    prompt = "wnet> "
    
    def __init__(self, engine: 'AnalysisEngine'):
        """
        Initialize the interactive shell
        
        Args:
            engine: The analysis engine instance
        """
        super().__init__()
        self.engine = engine
        self.running = True
        self.status_thread = None
        self.show_status = False
        self.status_interval = 3.0
        
        # Start status thread
        self._start_status_thread()
    
    def _start_status_thread(self):
        """Start background status thread"""
        self.status_thread = threading.Thread(
            target=self._status_updater,
            daemon=True
        )
        self.status_thread.start()
    
    def _status_updater(self):
        """Background thread for status updates"""
        try:
            while self.running:
                if self.show_status:
                    self._print_status()
                time.sleep(self.status_interval)
        except Exception as e:
            logger.error(f"Error in status updater: {e}")
    
    def _print_status(self):
        """Print current status"""
        try:
            status = self.engine.get_status()
            
            # Clear screen and move cursor to top-left
            sys.stdout.write("\033[2J\033[H")
            
            # Print status header
            print("═" * 50)
            print(f"Status: {'Running' if status['running'] else 'Stopped'}")
            print("═" * 50)
            
            # Print active interfaces
            print(f"Interfaces: {', '.join(status['interfaces'])}")
            
            # Print active clients
            print(f"Active clients: {status['active_clients']}")
            print(f"Disconnected clients: {status['disconnected_clients']}")
            
            # Print target APs
            print(f"Target APs: {status['target_aps']}")
            
            # Print attack stats
            print("\nAttack Statistics:")
            print(f"  Deauth packets sent: {status['attack_stats']['deauth_sent']}")
            print(f"  Disassoc packets sent: {status['attack_stats']['disassoc_sent']}")
            print(f"  Successful disconnects: {status['attack_stats']['successful_disconnects']}")
            print(f"  Failed disconnects: {status['attack_stats']['failed_disconnects']}")
            
            # Print mode
            print(f"\nMode: {status['mode']}")
            print(f"AI enabled: {status['ai_enabled']}")
            
            # Print timestamp
            print("\n" + "─" * 50)
            print(f"Last update: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("Press Ctrl+C to return to the command prompt")
            
        except Exception as e:
            print(f"Error getting status: {e}")
    
    def emptyline(self):
        """Handle empty line"""
        pass
    
    def do_exit(self, arg):
        """Exit the interactive shell"""
        print("Exiting...")
        self.running = False
        self.engine.stop()
        return True
    
    def do_quit(self, arg):
        """Exit the interactive shell"""
        return self.do_exit(arg)
    
    def do_status(self, arg):
        """
        Display current status
        
        Usage: status [toggle|on|off|interval <seconds>]
        """
        args = shlex.split(arg)
        
        if not args:
            # One-time status display
            self._print_status()
            return
        
        if args[0] == 'toggle':
            self.show_status = not self.show_status
            print(f"Status updates {'enabled' if self.show_status else 'disabled'}")
        
        elif args[0] == 'on':
            self.show_status = True
            print("Status updates enabled")
        
        elif args[0] == 'off':
            self.show_status = False
            print("Status updates disabled")
        
        elif args[0] == 'interval' and len(args) > 1:
            try:
                interval = float(args[1])
                if interval < 1.0:
                    print("Interval must be at least 1.0 seconds")
                else:
                    self.status_interval = interval
                    print(f"Status update interval set to {interval} seconds")
            except ValueError:
                print("Invalid interval value")
        
        else:
            print("Invalid arguments")
    
    def do_start(self, arg):
        """
        Start the framework
        
        Usage: start
        """
        if self.engine.running:
            print("Framework is already running")
            return
        
        print("Starting framework...")
        success = self.engine.start()
        
        if success:
            print("Framework started successfully")
        else:
            print("Failed to start framework")
    
    def do_stop(self, arg):
        """
        Stop the framework
        
        Usage: stop
        """
        if not self.engine.running:
            print("Framework is not running")
            return
        
        print("Stopping framework...")
        self.engine.stop()
        print("Framework stopped")
    
    def do_interfaces(self, arg):
        """
        List or select wireless interfaces
        
        Usage: 
          interfaces list
          interfaces select <interface1> [<interface2> ...]
          interfaces info <interface>
        """
        args = shlex.split(arg)
        
        if not args:
            print("Current interfaces:", ", ".join(self.engine.interfaces))
            return
        
        if args[0] == 'list':
            # Get available interfaces
            interfaces = self._get_available_interfaces()
            print("Available interfaces:")
            for interface in interfaces:
                print(f"  {interface}")
        
        elif args[0] == 'select' and len(args) > 1:
            # Select interfaces
            self.engine.interfaces = args[1:]
            print("Selected interfaces:", ", ".join(self.engine.interfaces))
        
        elif args[0] == 'info' and len(args) > 1:
            # Show interface info
            interface = args[1]
            
            if interface not in self.engine.interfaces:
                print(f"Interface {interface} is not selected")
                return
            
            # Get interface info
            try:
                channel = self.engine.channel_hopper.get_current_channel(interface)
                
                print(f"Interface: {interface}")
                print(f"Current channel: {channel}")
                
                # Get additional info if available
            except Exception as e:
                print(f"Error getting interface info: {e}")
        
        else:
            print("Invalid arguments")
    
    def _get_available_interfaces(self) -> List[str]:
        """Get list of available wireless interfaces"""
        try:
            import subprocess
            output = subprocess.check_output(['ip', 'link', 'show']).decode('utf-8')
            
            interfaces = []
            for line in output.splitlines():
                if ': ' in line:
                    interface = line.split(': ')[1]
                    interfaces.append(interface)
            
            return interfaces
        except Exception as e:
            logger.error(f"Error getting available interfaces: {e}")
            return []
    
    def do_target(self, arg):
        """
        Manage target APs
        
        Usage:
          target list
          target add <bssid> <essid> <channel>
          target remove <bssid>
          target clear
        """
        args = shlex.split(arg)
        
        if not args:
            # List current targets
            print("Current targets:")
            for bssid, channel in self.engine.target_aps.items():
                print(f"  {bssid} (Channel {channel})")
            return
        
        if args[0] == 'list':
            # List current targets
            print("Current targets:")
            for bssid, channel in self.engine.target_aps.items():
                print(f"  {bssid} (Channel {channel})")
        
        elif args[0] == 'add' and len(args) >= 4:
            # Add target AP
            bssid = args[1]
            essid = args[2]
            channel = int(args[3])
            
            self.engine.add_target_ap(bssid, essid, channel)
            print(f"Added target AP: {bssid} ({essid}) on channel {channel}")
        
        elif args[0] == 'remove' and len(args) >= 2:
            # Remove target AP
            bssid = args[1]
            
            if bssid in self.engine.target_aps:
                del self.engine.target_aps[bssid]
                print(f"Removed target AP: {bssid}")
            else:
                print(f"Target AP not found: {bssid}")
        
        elif args[0] == 'clear':
            # Clear all targets
            self.engine.target_aps = {}
            print("Cleared all target APs")
        
        else:
            print("Invalid arguments")
    
    def do_clients(self, arg):
        """
        Manage client tracking
        
        Usage:
          clients list [active|disconnected]
          clients info <mac_address>
          clients attack <mac_address>
        """
        args = shlex.split(arg)
        
        if not args:
            # List all clients
            print("Active clients:")
            for client in self.engine.active_clients:
                print(f"  {client}")
            
            print("\nDisconnected clients:")
            for client in self.engine.disconnected_clients:
                print(f"  {client}")
            
            return
        
        if args[0] == 'list':
            # List clients
            if len(args) > 1 and args[1] == 'active':
                print("Active clients:")
                for client in self.engine.active_clients:
                    print(f"  {client}")
            
            elif len(args) > 1 and args[1] == 'disconnected':
                print("Disconnected clients:")
                for client in self.engine.disconnected_clients:
                    print(f"  {client}")
            
            else:
                print("Active clients:")
                for client in self.engine.active_clients:
                    print(f"  {client}")
                
                print("\nDisconnected clients:")
                for client in self.engine.disconnected_clients:
                    print(f"  {client}")
        
        elif args[0] == 'info' and len(args) > 1:
            # Show client info
            client_mac = args[1]
            
            if not hasattr(self.engine, 'client_tracker') or not self.engine.client_tracker:
                print("Client tracker not available")
                return
            
            client_info = self.engine.client_tracker.get_client_info(client_mac)
            
            if not client_info:
                print(f"Client not found: {client_mac}")
                return
            
            print(f"Client: {client_mac}")
            print(f"Active: {client_info.get('active', False)}")
            print(f"First seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(client_info.get('first_seen', 0)))}")
            print(f"Last seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(client_info.get('last_seen', 0)))}")
            print(f"Signal strength: {client_info.get('signal_strength', 'N/A')}")
            print(f"Channel: {client_info.get('channel', 'N/A')}")
            print(f"Attack count: {client_info.get('attack_count', 0)}")
            print(f"Reconnect count: {client_info.get('reconnect_count', 0)}")
            
            if 'avg_reconnect_time' in client_info and client_info['avg_reconnect_time'] > 0:
                print(f"Average reconnect time: {client_info['avg_reconnect_time']:.2f} seconds")
        
        elif args[0] == 'attack' and len(args) > 1:
            # Attack a client
            client_mac = args[1]
            
            # Check if engine is running
            if not self.engine.running:
                print("Framework is not running")
                return
            
            # Get associated AP
            ap_mac = None
            if hasattr(self.engine, 'client_tracker') and self.engine.client_tracker:
                client_info = self.engine.client_tracker.get_client_info(client_mac)
                if client_info:
                    ap_mac = client_info.get('ap_mac')
            
            if not ap_mac:
                print("Client not associated with a known AP")
                return
            
            # Get channel
            channel = self.engine.target_aps.get(ap_mac)
            if not channel:
                print("Associated AP not in target list")
                return
            
            print(f"Attacking client {client_mac} on {ap_mac} (Channel {channel})...")
            
            # Use cognitive engine if available
            if hasattr(self.engine, 'cognitive_engine') and self.engine.cognitive_engine:
                strategy = self.engine.cognitive_engine.select_action(client_mac)
                self.engine._execute_attack(client_mac, ap_mac, channel, strategy)
                print(f"Attack initiated with strategy: {strategy.get('vector', 'deauth')} ({strategy.get('count', 5)} packets)")
            else:
                # Use default strategy
                strategy = self.engine._get_default_strategy(client_mac)
                self.engine._execute_attack(client_mac, ap_mac, channel, strategy)
                print(f"Attack initiated with default strategy: {strategy.get('vector', 'deauth')} ({strategy.get('count', 5)} packets)")
        
        else:
            print("Invalid arguments")
    
    def do_channel(self, arg):
        """
        Manage channel hopping
        
        Usage:
          channel list
          channel set <interface> <channel>
          channel hop [start|stop] [<channel1> <channel2> ...]
        """
        args = shlex.split(arg)
        
        if not args:
            # Show current channels
            if not hasattr(self.engine, 'channel_hopper') or not self.engine.channel_hopper:
                print("Channel hopper not available")
                return
            
            print("Current channels:")
            for interface, channel in self.engine.channel_hopper.current_channels.items():
                print(f"  {interface}: {channel or 'Unknown'}")
            
            return
        
        if args[0] == 'list':
            # Show available channels
            print("Available channels:")
            print("  2.4 GHz: 1-13")
            print("  5 GHz: 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165")
        
        elif args[0] == 'set' and len(args) >= 3:
            # Set channel for an interface
            interface = args[1]
            channel = int(args[2])
            
            if not hasattr(self.engine, 'channel_hopper') or not self.engine.channel_hopper:
                print("Channel hopper not available")
                return
            
            if interface not in self.engine.interfaces:
                print(f"Interface {interface} not found")
                return
            
            success = self.engine.channel_hopper.set_channel(interface, channel)
            
            if success:
                print(f"Set {interface} to channel {channel}")
            else:
                print(f"Failed to set {interface} to channel {channel}")
        
        elif args[0] == 'hop':
            # Channel hopping controls
            if not hasattr(self.engine, 'channel_hopper') or not self.engine.channel_hopper:
                print("Channel hopper not available")
                return
            
            if len(args) > 1 and args[1] == 'start':
                # Start channel hopping
                channels = None
                if len(args) > 2:
                    try:
                        channels = [int(ch) for ch in args[2:]]
                    except ValueError:
                        print("Invalid channel values")
                        return
                
                success = self.engine.channel_hopper.hop_between_channels(channels)
                
                if success:
                    print(f"Started channel hopping with {len(channels or []) or 'default'} channels")
                else:
                    print("Failed to start channel hopping")
            
            elif len(args) > 1 and args[1] == 'stop':
                # Stop channel hopping
                success = self.engine.channel_hopper.stop_hopping()
                
                if success:
                    print("Stopped channel hopping")
                else:
                    print("Failed to stop channel hopping")
            
            else:
                # Toggle channel hopping with optional channel list
                channels = None
                if len(args) > 1:
                    try:
                        channels = [int(ch) for ch in args[1:]]
                    except ValueError:
                        print("Invalid channel values")
                        return
                
                success = self.engine.channel_hopper.hop_between_channels(channels)
                
                if success:
                    print(f"Started channel hopping with {len(channels or []) or 'default'} channels")
                else:
                    print("Failed to start channel hopping")
        
        else:
            print("Invalid arguments")
    
    def do_mode(self, arg):
        """
        Set operation mode
        
        Usage:
          mode [normal|aggressive|stealth]
          mode ai [on|off]
        """
        args = shlex.split(arg)
        
        if not args:
            # Show current mode
            mode = "normal"
            if self.engine.aggressive_mode:
                mode = "aggressive"
            elif self.engine.stealth_mode:
                mode = "stealth"
            
            print(f"Current mode: {mode}")
            print(f"AI enabled: {self.engine.enable_ai}")
            return
        
        if args[0] == 'normal':
            # Set normal mode
            self.engine.aggressive_mode = False
            self.engine.stealth_mode = False
            print("Set normal mode")
        
        elif args[0] == 'aggressive':
            # Set aggressive mode
            self.engine.aggressive_mode = True
            self.engine.stealth_mode = False
            print("Set aggressive mode")
        
        elif args[0] == 'stealth':
            # Set stealth mode
            self.engine.aggressive_mode = False
            self.engine.stealth_mode = True
            print("Set stealth mode")
        
        elif args[0] == 'ai':
            # AI mode controls
            if len(args) > 1:
                if args[1] == 'on':
                    self.engine.enable_ai = True
                    print("AI components enabled")
                elif args[1] == 'off':
                    self.engine.enable_ai = False
                    print("AI components disabled")
                else:
                    print("Invalid argument for AI mode")
            else:
                print(f"AI currently: {'enabled' if self.engine.enable_ai else 'disabled'}")
        
        else:
            print("Invalid mode")
    
    def do_scan(self, arg):
        """
        Scan for wireless networks
        
        Usage:
          scan [start|stop] [channel <channel>]
        """
        args = shlex.split(arg)
        
        # This feature requires additional implementation in the engine
        print("Scan functionality not yet implemented")
    
    def do_stats(self, arg):
        """
        Show statistics
        
        Usage:
          stats [attacks|clients|performance]
        """
        args = shlex.split(arg)
        
        if not args:
            # Show all stats
            print("Attack Statistics:")
            print(f"  Deauth packets sent: {self.engine.attack_stats['deauth_sent']}")
            print(f"  Disassoc packets sent: {self.engine.attack_stats['disassoc_sent']}")
            print(f"  Successful disconnects: {self.engine.attack_stats['successful_disconnects']}")
            print(f"  Failed disconnects: {self.engine.attack_stats['failed_disconnects']}")
            
            if hasattr(self.engine, 'client_tracker') and self.engine.client_tracker:
                metrics = self.engine.client_tracker.get_metrics()
                
                print("\nClient Tracking:")
                print(f"  Total tracked clients: {metrics.get('tracked_clients', 0)}")
                print(f"  Active clients: {metrics.get('active_clients', 0)}")
                print(f"  Disconnected clients: {metrics.get('disconnected_clients', 0)}")
                print(f"  Expired clients: {metrics.get('expired_clients', 0)}")
            
            return
        
        if args[0] == 'attacks':
            # Show attack stats
            print("Attack Statistics:")
            print(f"  Deauth packets sent: {self.engine.attack_stats['deauth_sent']}")
            print(f"  Disassoc packets sent: {self.engine.attack_stats['disassoc_sent']}")
            print(f"  Successful disconnects: {self.engine.attack_stats['successful_disconnects']}")
            print(f"  Failed disconnects: {self.engine.attack_stats['failed_disconnects']}")
            
            # Success rate
            total_attempts = (self.engine.attack_stats['successful_disconnects'] + 
                            self.engine.attack_stats['failed_disconnects'])
            if total_attempts > 0:
                success_rate = (self.engine.attack_stats['successful_disconnects'] / 
                               total_attempts * 100)
                print(f"  Success rate: {success_rate:.1f}%")
        
        elif args[0] == 'clients':
            # Show client stats
            if hasattr(self.engine, 'client_tracker') and self.engine.client_tracker:
                metrics = self.engine.client_tracker.get_metrics()
                
                print("Client Tracking:")
                print(f"  Total tracked clients: {metrics.get('tracked_clients', 0)}")
                print(f"  Active clients: {metrics.get('active_clients', 0)}")
                print(f"  Disconnected clients: {metrics.get('disconnected_clients', 0)}")
                print(f"  Expired clients: {metrics.get('expired_clients', 0)}")
            else:
                print("Client tracker not available")
        
        elif args[0] == 'performance':
            # Show performance stats
            if hasattr(self.engine, 'cognitive_engine') and self.engine.cognitive_engine:
                insights = self.engine.cognitive_engine.get_strategy_insights()
                
                print("Strategy Performance:")
                print("  Top performing vectors:")
                for vector, success_rate in insights.get('vector_performance', {}).items():
                    print(f"    {vector}: {success_rate*100:.1f}%")
                
                print("\n  Top performing actions:")
                for action in insights.get('top_actions', []):
                    print(f"    {action['vector']} (count: {action['count']}): {action['success_rate']*100:.1f}%")
                
                print("\n  Device category effectiveness:")
                for category, effectiveness in insights.get('category_effectiveness', {}).items():
                    print(f"    {category}: {effectiveness:.2f}")
            else:
                print("Cognitive engine not available")
        
        else:
            print("Invalid argument")
    
    def do_config(self, arg):
        """
        Manage configuration
        
        Usage:
          config show [<key>]
          config set <key> <value>
          config save [<filename>]
          config load <filename>
          config reset
        """
        args = shlex.split(arg)
        
        if not args:
            # Show all config
            if hasattr(self.engine, 'config'):
                config = self.engine.config
                print("Current configuration:")
                print(json.dumps(config, indent=2))
            else:
                print("Configuration manager not available")
            return
        
        if not hasattr(self.engine, 'config'):
            print("Configuration manager not available")
            return
        
        if args[0] == 'show':
            # Show config value(s)
            if len(args) > 1:
                key = args[1]
                value = self.engine.config.get_value(key)
                print(f"{key}: {value}")
            else:
                config = self.engine.config.get_all()
                print("Current configuration:")
                print(json.dumps(config, indent=2))
        
        elif args[0] == 'set' and len(args) >= 3:
            # Set config value
            key = args[1]
            
            # Try to parse as JSON first
            try:
                value = json.loads(' '.join(args[2:]))
            except json.JSONDecodeError:
                # If not valid JSON, use as string
                value = ' '.join(args[2:])
            
            success = self.engine.config.set_value(key, value)
            
            if success:
                print(f"Set {key} = {value}")
            else:
                print(f"Failed to set {key}")
        
        elif args[0] == 'save':
            # Save config
            filename = args[1] if len(args) > 1 else None
            
            success = self.engine.config.save_config(filename)
            
            if success:
                print(f"Saved configuration to {filename or 'default path'}")
            else:
                print("Failed to save configuration")
        
        elif args[0] == 'load' and len(args) > 1:
            # Load config
            filename = args[1]
            
            success = self.engine.config.load_config(filename)
            
            if success:
                print(f"Loaded configuration from {filename}")
            else:
                print(f"Failed to load configuration from {filename}")
        
        elif args[0] == 'reset':
            # Reset config
            success = self.engine.config.reset_to_defaults()
            
            if success:
                print("Reset configuration to defaults")
            else:
                print("Failed to reset configuration")
        
        else:
            print("Invalid arguments")
    
    def do_help(self, arg):
        """
        Show help for commands
        
        Usage: help [command]
        """
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            # Show general help
            print("Available commands:")
            print("  status     - Display current status")
            print("  start      - Start the framework")
            print("  stop       - Stop the framework")
            print("  interfaces - Manage wireless interfaces")
            print("  target     - Manage target APs")
            print("  clients    - Manage client tracking")
            print("  channel    - Manage channel hopping")
            print("  mode       - Set operation mode")
            print("  scan       - Scan for wireless networks")
            print("  stats      - Show statistics")
            print("  config     - Manage configuration")
            print("  help       - Show help for commands")
            print("  exit       - Exit the interactive shell")
            print("\nUse 'help <command>' for more information on a specific command")