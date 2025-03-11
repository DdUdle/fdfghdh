"""
Command-line interface components for interactive control
and configuration of the analysis framework.
"""

# Export CLI components
from .argparser import parse_arguments
from .interactive import InteractiveShell

__all__ = [
    'parse_arguments',
    'InteractiveShell',
    'start_interactive_session'
]

def start_interactive_session(engine):
    """
    Start an interactive shell session with the given engine
    
    Args:
        engine: AnalysisEngine instance
        
    Returns:
        bool: True if session ended normally, False otherwise
    """
    try:
        shell = InteractiveShell(engine)
        shell.cmdloop()
        return True
    except KeyboardInterrupt:
        print("\nInteractive session terminated by user")
        return True
    except Exception as e:
        from ..utils.logging import setup_logger
        logger = setup_logger(__name__)
        logger.error(f"Error in interactive session: {e}")
        return False 