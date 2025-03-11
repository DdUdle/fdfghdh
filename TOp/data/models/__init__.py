"""
Model management for the Wireless Network Analysis Framework.
"""

import os
import json
import glob

MODELS_DIR = os.path.dirname(__file__)

def get_available_models():
    """Get list of available models"""
    model_files = glob.glob(os.path.join(MODELS_DIR, '*.pt')) + \
                 glob.glob(os.path.join(MODELS_DIR, '*.npz')) + \
                 glob.glob(os.path.join(MODELS_DIR, '*.pkl'))
    
    models = {}
    for model_path in model_files:
        model_name = os.path.basename(model_path)
        model_type = os.path.splitext(model_name)[1][1:]  # Extension without dot
        
        if model_type not in models:
            models[model_type] = []
        
        models[model_type].append(model_name)
    
    return models

def get_model_metadata_file():
    """Get path to model metadata file"""
    return os.path.join(MODELS_DIR, 'model_metadata.json')

def load_model_metadata():
    """Load model metadata"""
    metadata_file = get_model_metadata_file()
    
    if not os.path.exists(metadata_file):
        return {}
    
    try:
        with open(metadata_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        from ...utils.logging import setup_logger
        logger = setup_logger(__name__)
        logger.error(f"Error loading model metadata: {e}")
        return {}

def save_model_metadata(metadata):
    """Save model metadata"""
    metadata_file = get_model_metadata_file()
    
    try:
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        return True
    except Exception as e:
        from ...utils.logging import setup_logger
        logger = setup_logger(__name__)
        logger.error(f"Error saving model metadata: {e}")
        return False 