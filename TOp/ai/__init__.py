"""
Advanced machine learning components for behavioral analysis,
temporal pattern recognition, and adaptive strategy optimization.
"""

import importlib.util
import sys
import os

# Test for numpy availability
NUMPY_AVAILABLE = importlib.util.find_spec("numpy") is not None

# Test for PyTorch availability
TORCH_AVAILABLE = importlib.util.find_spec("torch") is not None

# Define ML capabilities based on available libraries
ML_CAPABILITIES_AVAILABLE = NUMPY_AVAILABLE

# Export AI components with graceful degradation if dependencies missing
from .pattern_miner import PatternMiner as TemporalPatternMiner

if TORCH_AVAILABLE:
    from .ml_models import DeepQNetwork, ModelManager
    from .cognitive_engine import CognitiveEngine
    from .strategy_optimizer import StrategyOptimizer
    
    # Эти классы мы добавим, если они есть в соответствующих файлах
    try:
        from .ml_models import SequenceModel, DeviceBehaviorModel
        __all__ = [
            'TemporalPatternMiner',
            'CognitiveEngine',
            'StrategyOptimizer',
            'DeepQNetwork',
            'SequenceModel',
            'DeviceBehaviorModel',
            'ModelManager',
            'NUMPY_AVAILABLE',
            'TORCH_AVAILABLE',
            'ML_CAPABILITIES_AVAILABLE'
        ]
    except ImportError:
        __all__ = [
            'TemporalPatternMiner',
            'CognitiveEngine',
            'StrategyOptimizer',
            'DeepQNetwork',
            'ModelManager',
            'NUMPY_AVAILABLE',
            'TORCH_AVAILABLE',
            'ML_CAPABILITIES_AVAILABLE'
        ]
else:
    # Import limited functionality for environments without PyTorch
    from .cognitive_engine import CognitiveEngine
    from .strategy_optimizer import StrategyOptimizer
    
    __all__ = [
        'TemporalPatternMiner',
        'CognitiveEngine',
        'StrategyOptimizer',
        'NUMPY_AVAILABLE',
        'TORCH_AVAILABLE',
        'ML_CAPABILITIES_AVAILABLE'
    ]

def initialize_ai_components(model_dir=None):
    """Initialize AI components with optional model directory"""
    from ..utils.logging import setup_logger
    logger = setup_logger(__name__)
    
    if not ML_CAPABILITIES_AVAILABLE:
        logger.warning("Machine learning capabilities limited - numpy not available")
        return False
    
    if not TORCH_AVAILABLE:
        logger.warning("Advanced neural network capabilities disabled - PyTorch not available")
    
    if model_dir and os.path.exists(model_dir):
        if TORCH_AVAILABLE:
            try:
                from .ml_models import ModelManager
                manager = ModelManager(model_dir)
                logger.info(f"AI model directory initialized: {model_dir}")
                return True
            except Exception as e:
                logger.error(f"Error initializing model directory: {e}")
                return False
    
    return ML_CAPABILITIES_AVAILABLE 