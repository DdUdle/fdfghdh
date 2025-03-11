"""
Wireless Network Analysis Framework - Machine Learning Models

This module implements neural network models for reinforcement learning and
pattern recognition to enhance adaptive decision making.
"""

import os
import time
import logging
import pickle
import math
import random
from typing import Dict, List, Tuple, Optional, Union, Any
import hashlib

# Try to import ML libraries - graceful fallback if unavailable
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from ..utils.logging import setup_logger

# Configure logger
logger = setup_logger(__name__)

class DeepQNetwork(nn.Module):
    """Neural network for Q-value prediction in reinforcement learning"""
    
    def __init__(self, input_dim: int, output_dim: int, hidden_dims: List[int] = [128, 64]):
        """
        Initialize the DQN network
        
        Args:
            input_dim: Input dimension (state features)
            output_dim: Output dimension (action space size)
            hidden_dims: Dimensions of hidden layers
        """
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch is required for DeepQNetwork")
            
        super(DeepQNetwork, self).__init__()
        
        # Build network layers
        layers = []
        prev_dim = input_dim
        
        for dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, dim))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(0.2))  # Add dropout for regularization
            prev_dim = dim
        
        layers.append(nn.Linear(prev_dim, output_dim))
        
        self.network = nn.Sequential(*layers)
        
        # Initialize weights
        self._init_weights()
    
    def _init_weights(self):
        """Initialize network weights for better convergence"""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                nn.init.zeros_(module.bias)
    
    def forward(self, x):
        """
        Forward pass through the network
        
        Args:
            x: Input tensor
            
        Returns:
            Tensor: Q-values for each action
        """
        return self.network(x)

class SequenceModel(nn.Module):
    """LSTM-based sequence model for temporal pattern analysis"""
    
    def __init__(self, input_dim: int, hidden_dim: int = 64, num_layers: int = 2, dropout: float = 0.2):
        """
        Initialize the sequence model
        
        Args:
            input_dim: Input dimension
            hidden_dim: Hidden dimension
            num_layers: Number of LSTM layers
            dropout: Dropout probability
        """
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch is required for SequenceModel")
            
        super(SequenceModel, self).__init__()
        
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0
        )
        
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1)
        )
        
        self.output = nn.Linear(hidden_dim, 1)  # Predict success probability
    
    def forward(self, x, hidden=None):
        """
        Forward pass through the network
        
        Args:
            x: Input tensor (batch_size, seq_len, input_dim)
            hidden: Initial hidden state
            
        Returns:
            Tuple: (output, hidden_state)
        """
        # x shape: [batch_size, seq_len, input_dim]
        lstm_out, hidden = self.lstm(x, hidden)
        
        # Apply attention mechanism
        attention_scores = self.attention(lstm_out).squeeze(-1)
        attention_weights = F.softmax(attention_scores, dim=1).unsqueeze(1)
        
        # Weighted sum of LSTM outputs
        context = torch.bmm(attention_weights, lstm_out).squeeze(1)
        
        # Final prediction
        output = self.output(context)
        return output, hidden

class DeviceBehaviorModel(nn.Module):
    """Neural network for learning device behavior patterns"""
    
    def __init__(self, feature_dim: int, embedding_dim: int = 32, hidden_dim: int = 64):
        """
        Initialize the device behavior model
        
        Args:
            feature_dim: Feature dimension
            embedding_dim: Embedding dimension for categorical features
            hidden_dim: Hidden dimension
        """
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch is required for DeviceBehaviorModel")
            
        super(DeviceBehaviorModel, self).__init__()
        
        # Feature embeddings for categorical features
        self.category_embedding = nn.Embedding(10, embedding_dim)  # Assume max 10 categories
        self.vendor_embedding = nn.Embedding(20, embedding_dim)    # Assume max 20 vendors
        
        # Combined input dimension
        combined_dim = feature_dim - 2 + (embedding_dim * 2)  # -2 for categorical, +2*embedding for embeddings
        
        # Encoder network
        self.encoder = nn.Sequential(
            nn.Linear(combined_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU()
        )
        
        # Decoder for reconstruction
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim // 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, combined_dim),
            nn.Sigmoid()  # Assume normalized features
        )
        
        # Anomaly detection head
        self.anomaly_head = nn.Sequential(
            nn.Linear(hidden_dim // 2, hidden_dim // 4),
            nn.ReLU(),
            nn.Linear(hidden_dim // 4, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x, cat_indices):
        """
        Forward pass through the network
        
        Args:
            x: Input tensor of continuous features
            cat_indices: Tuple of (category_idx, vendor_idx)
            
        Returns:
            Tuple: (reconstruction, anomaly_score, latent)
        """
        category_idx, vendor_idx = cat_indices
        
        # Get embeddings
        cat_embedding = self.category_embedding(category_idx)
        vendor_embedding = self.vendor_embedding(vendor_idx)
        
        # Combine continuous features and embeddings
        combined = torch.cat([x, cat_embedding, vendor_embedding], dim=1)
        
        # Encode
        latent = self.encoder(combined)
        
        # Decode for reconstruction
        reconstruction = self.decoder(latent)
        
        # Calculate anomaly score
        anomaly_score = self.anomaly_head(latent)
        
        return reconstruction, anomaly_score, latent

class ReplayBuffer:
    """Experience replay buffer for reinforcement learning"""
    
    def __init__(self, capacity: int = 10000):
        """
        Initialize the replay buffer
        
        Args:
            capacity: Maximum buffer capacity
        """
        self.capacity = capacity
        self.buffer = []
        self.position = 0
    
    def push(self, state, action, reward, next_state, done):
        """
        Add a transition to the buffer
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode is done
        """
        if len(self.buffer) < self.capacity:
            self.buffer.append(None)
        
        self.buffer[self.position] = (state, action, reward, next_state, done)
        self.position = (self.position + 1) % self.capacity
    
    def sample(self, batch_size: int):
        """
        Sample a batch of transitions
        
        Args:
            batch_size: Number of transitions to sample
            
        Returns:
            Tuple: Batch of (state, action, reward, next_state, done)
        """
        batch = random.sample(self.buffer, min(batch_size, len(self.buffer)))
        state, action, reward, next_state, done = zip(*batch)
        return state, action, reward, next_state, done
    
    def __len__(self):
        """Get buffer length"""
        return len(self.buffer)

class ModelManager:
    """Manager for creating, training, and saving/loading models"""
    
    def __init__(self, save_dir: str = None):
        """
        Initialize the model manager
        
        Args:
            save_dir: Directory to save models
        """
        self.save_dir = save_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'models')
        
        # Create save directory if it doesn't exist
        if not os.path.exists(self.save_dir):
            try:
                os.makedirs(self.save_dir)
            except Exception as e:
                logger.warning(f"Could not create save directory: {e}")
        
        # Determine device for PyTorch
        self.device = None
        if TORCH_AVAILABLE:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"Using device: {self.device}")
    
    def create_dqn(self, input_dim: int, output_dim: int, hidden_dims: List[int] = None) -> Optional[DeepQNetwork]:
        """
        Create a Deep Q-Network
        
        Args:
            input_dim: Input dimension
            output_dim: Output dimension
            hidden_dims: Hidden layer dimensions
            
        Returns:
            DeepQNetwork: Created model or None if unavailable
        """
        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available - cannot create DQN")
            return None
        
        try:
            # Default hidden dimensions if not specified
            if hidden_dims is None:
                hidden_dims = [128, 64]
            
            # Create the model
            model = DeepQNetwork(input_dim, output_dim, hidden_dims).to(self.device)
            logger.info(f"Created DQN with architecture: {input_dim} -> {hidden_dims} -> {output_dim}")
            
            return model
        except Exception as e:
            logger.error(f"Error creating DQN: {e}")
            return None
    
    def create_sequence_model(self, input_dim: int, hidden_dim: int = 64,
                            num_layers: int = 2) -> Optional[SequenceModel]:
        """
        Create a sequence model
        
        Args:
            input_dim: Input dimension
            hidden_dim: Hidden dimension
            num_layers: Number of LSTM layers
            
        Returns:
            SequenceModel: Created model or None if unavailable
        """
        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available - cannot create sequence model")
            return None
        
        try:
            # Create the model
            model = SequenceModel(input_dim, hidden_dim, num_layers).to(self.device)
            logger.info(f"Created sequence model with architecture: {input_dim} -> {hidden_dim} ({num_layers} layers)")
            
            return model
        except Exception as e:
            logger.error(f"Error creating sequence model: {e}")
            return None
    
    def create_device_behavior_model(self, feature_dim: int) -> Optional[DeviceBehaviorModel]:
        """
        Create a device behavior model
        
        Args:
            feature_dim: Feature dimension
            
        Returns:
            DeviceBehaviorModel: Created model or None if unavailable
        """
        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available - cannot create device behavior model")
            return None
        
        try:
            # Create the model
            model = DeviceBehaviorModel(feature_dim).to(self.device)
            logger.info(f"Created device behavior model with feature dimension: {feature_dim}")
            
            return model
        except Exception as e:
            logger.error(f"Error creating device behavior model: {e}")
            return None
    
    def save_model(self, model: nn.Module, model_name: str) -> bool:
        """
        Save a PyTorch model
        
        Args:
            model: Model to save
            model_name: Name of the model
            
        Returns:
            bool: True if saved successfully, False otherwise
        """
        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available - cannot save model")
            return False
        
        try:
            # Generate a unique filename with timestamp
            timestamp = int(time.time())
            filename = f"{model_name}_{timestamp}.pt"
            path = os.path.join(self.save_dir, filename)
            
            # Save the model
            torch.save(model.state_dict(), path)
            logger.info(f"Saved model {model_name} to {path}")
            
            return True
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, model: nn.Module, model_name: str, version: str = 'latest') -> bool:
        """
        Load a PyTorch model
        
        Args:
            model: Model to load into
            model_name: Name of the model
            version: Version to load ('latest' or specific timestamp)
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available - cannot load model")
            return False
        
        try:
            if version == 'latest':
                # Find the latest version
                model_files = [f for f in os.listdir(self.save_dir) 
                             if f.startswith(model_name) and f.endswith('.pt')]
                
                if not model_files:
                    logger.warning(f"No saved models found for {model_name}")
                    return False
                
                # Sort by timestamp (descending)
                model_files.sort(reverse=True)
                path = os.path.join(self.save_dir, model_files[0])
            else:
                # Use specific version
                path = os.path.join(self.save_dir, f"{model_name}_{version}.pt")
                
                if not os.path.exists(path):
                    logger.warning(f"Model version not found: {path}")
                    return False
            
            # Load the model
            model.load_state_dict(torch.load(path, map_location=self.device))
            logger.info(f"Loaded model {model_name} from {path}")
            
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def save_numpy_model(self, model: Any, model_name: str) -> bool:
        """
        Save a NumPy-based model
        
        Args:
            model: Model to save
            model_name: Name of the model
            
        Returns:
            bool: True if saved successfully, False otherwise
        """
        if not NUMPY_AVAILABLE:
            logger.warning("NumPy not available - cannot save model")
            return False
        
        try:
            # Generate a unique filename with timestamp
            timestamp = int(time.time())
            filename = f"{model_name}_{timestamp}.npz"
            path = os.path.join(self.save_dir, filename)
            
            # Save the model
            np.savez(path, **model)
            logger.info(f"Saved NumPy model {model_name} to {path}")
            
            return True
        except Exception as e:
            logger.error(f"Error saving NumPy model: {e}")
            return False
    
    def load_numpy_model(self, model_name: str, version: str = 'latest') -> Optional[Dict]:
        """
        Load a NumPy-based model
        
        Args:
            model_name: Name of the model
            version: Version to load ('latest' or specific timestamp)
            
        Returns:
            dict: Loaded model or None if unavailable
        """
        if not NUMPY_AVAILABLE:
            logger.warning("NumPy not available - cannot load model")
            return None
        
        try:
            if version == 'latest':
                # Find the latest version
                model_files = [f for f in os.listdir(self.save_dir) 
                             if f.startswith(model_name) and f.endswith('.npz')]
                
                if not model_files:
                    logger.warning(f"No saved models found for {model_name}")
                    return None
                
                # Sort by timestamp (descending)
                model_files.sort(reverse=True)
                path = os.path.join(self.save_dir, model_files[0])
            else:
                # Use specific version
                path = os.path.join(self.save_dir, f"{model_name}_{version}.npz")
                
                if not os.path.exists(path):
                    logger.warning(f"Model version not found: {path}")
                    return None
            
            # Load the model
            with np.load(path) as data:
                model = {key: data[key] for key in data.files}
            
            logger.info(f"Loaded NumPy model {model_name} from {path}")
            
            return model
        except Exception as e:
            logger.error(f"Error loading NumPy model: {e}")
            return None
    
    def save_pickle_model(self, model: Any, model_name: str) -> bool:
        """
        Save a model using pickle
        
        Args:
            model: Model to save
            model_name: Name of the model
            
        Returns:
            bool: True if saved successfully, False otherwise
        """
        try:
            # Generate a unique filename with timestamp
            timestamp = int(time.time())
            filename = f"{model_name}_{timestamp}.pkl"
            path = os.path.join(self.save_dir, filename)
            
            # Save the model
            with open(path, 'wb') as f:
                pickle.dump(model, f)
            
            logger.info(f"Saved pickle model {model_name} to {path}")
            
            return True
        except Exception as e:
            logger.error(f"Error saving pickle model: {e}")
            return False
    
    def load_pickle_model(self, model_name: str, version: str = 'latest') -> Optional[Any]:
        """
        Load a model using pickle
        
        Args:
            model_name: Name of the model
            version: Version to load ('latest' or specific timestamp)
            
        Returns:
            Any: Loaded model or None if unavailable
        """
        try:
            if version == 'latest':
                # Find the latest version
                model_files = [f for f in os.listdir(self.save_dir) 
                             if f.startswith(model_name) and f.endswith('.pkl')]
                
                if not model_files:
                    logger.warning(f"No saved models found for {model_name}")
                    return None
                
                # Sort by timestamp (descending)
                model_files.sort(reverse=True)
                path = os.path.join(self.save_dir, model_files[0])
            else:
                # Use specific version
                path = os.path.join(self.save_dir, f"{model_name}_{version}.pkl")
                
                if not os.path.exists(path):
                    logger.warning(f"Model version not found: {path}")
                    return None
            
            # Load the model
            with open(path, 'rb') as f:
                model = pickle.load(f)
            
            logger.info(f"Loaded pickle model {model_name} from {path}")
            
            return model
        except Exception as e:
            logger.error(f"Error loading pickle model: {e}")
            return None
    
    def get_optimizer(self, model: nn.Module, learning_rate: float = 0.001) -> Optional[optim.Optimizer]:
        """
        Get an optimizer for a PyTorch model
        
        Args:
            model: Model to optimize
            learning_rate: Learning rate
            
        Returns:
            optim.Optimizer: Optimizer or None if unavailable
        """
        if not TORCH_AVAILABLE:
            logger.warning("PyTorch not available - cannot create optimizer")
            return None
        
        try:
            # Create the optimizer
            optimizer = optim.Adam(model.parameters(), lr=learning_rate)
            return optimizer
        except Exception as e:
            logger.error(f"Error creating optimizer: {e}")
            return None
    
    def get_model_hash(self, model: nn.Module) -> str:
        """
        Get a hash of a PyTorch model
        
        Args:
            model: Model to hash
            
        Returns:
            str: Model hash
        """
        if not TORCH_AVAILABLE:
            return "unknown"
        
        try:
            # Get model parameters as bytes
            params = []
            for param in model.parameters():
                params.append(param.data.cpu().numpy().tobytes())
            
            # Create hash
            hasher = hashlib.md5()
            for param in params:
                hasher.update(param)
            
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing model: {e}")
            return "unknown"
    
    def get_available_models(self, model_name: str = None) -> Dict[str, List[str]]:
        """
        Get available saved models
        
        Args:
            model_name: Filter by model name (optional)
            
        Returns:
            dict: Dictionary of model name -> list of versions
        """
        try:
            model_dict = {}
            
            # Get all model files
            for filename in os.listdir(self.save_dir):
                if filename.endswith(('.pt', '.npz', '.pkl')):
                    # Extract model name and version
                    parts = filename.rsplit('_', 1)
                    if len(parts) == 2:
                        name = parts[0]
                        version = parts[1].split('.')[0]
                        
                        # Skip if not matching model_name filter
                        if model_name and name != model_name:
                            continue
                        
                        # Add to dictionary
                        if name not in model_dict:
                            model_dict[name] = []
                        model_dict[name].append(version)
            
            # Sort versions
            for name in model_dict:
                model_dict[name].sort(reverse=True)
            
            return model_dict
        except Exception as e:
            logger.error(f"Error getting available models: {e}")
            return {}

# Fallback implementations if ML libraries are not available
class FallbackModels:
    """Provides fallback implementations when ML libraries are unavailable"""
    
    @staticmethod
    def simple_model(input_dim: int, output_dim: int) -> Dict:
        """
        Create a simple fallback model
        
        Args:
            input_dim: Input dimension
            output_dim: Output dimension
            
        Returns:
            dict: Simple model structure
        """
        # Create random weights and biases
        weights = [[random.uniform(-0.1, 0.1) for _ in range(input_dim)] for _ in range(output_dim)]
        biases = [random.uniform(-0.1, 0.1) for _ in range(output_dim)]
        
        return {
            'weights': weights,
            'biases': biases,
            'input_dim': input_dim,
            'output_dim': output_dim,
            'type': 'linear'
        }
    
    @staticmethod
    def predict(model: Dict, inputs: List[float]) -> List[float]:
        """
        Make predictions with a simple model
        
        Args:
            model: Simple model structure
            inputs: Input values
            
        Returns:
            list: Predicted values
        """
        if model['type'] != 'linear':
            raise ValueError(f"Unsupported model type: {model['type']}")
        
        if len(inputs) != model['input_dim']:
            raise ValueError(f"Expected {model['input_dim']} inputs, got {len(inputs)}")
        
        # Calculate outputs
        outputs = []
        for i in range(model['output_dim']):
            # Dot product of inputs and weights
            output = sum(inputs[j] * model['weights'][i][j] for j in range(model['input_dim']))
            # Add bias
            output += model['biases'][i]
            # Apply ReLU activation
            output = max(0, output)
            outputs.append(output)
        
        return outputs
    
    @staticmethod
    def update(model: Dict, inputs: List[float], targets: List[float], learning_rate: float = 0.01) -> Dict:
        """
        Update a simple model using gradient descent
        
        Args:
            model: Simple model structure
            inputs: Input values
            targets: Target values
            learning_rate: Learning rate
            
        Returns:
            dict: Updated model
        """
        if model['type'] != 'linear':
            raise ValueError(f"Unsupported model type: {model['type']}")
        
        if len(inputs) != model['input_dim']:
            raise ValueError(f"Expected {model['input_dim']} inputs, got {len(inputs)}")
        
        if len(targets) != model['output_dim']:
            raise ValueError(f"Expected {model['output_dim']} targets, got {len(targets)}")
        
        # Get predictions
        predictions = FallbackModels.predict(model, inputs)
        
        # Calculate errors
        errors = [targets[i] - predictions[i] for i in range(model['output_dim'])]
        
        # Update weights and biases
        for i in range(model['output_dim']):
            # Calculate gradient direction
            gradient_direction = 1 if errors[i] > 0 else -1 if errors[i] < 0 else 0
            
            # Skip if no error
            if gradient_direction == 0:
                continue
            
            # Update weights
            for j in range(model['input_dim']):
                model['weights'][i][j] += learning_rate * gradient_direction * inputs[j]
            
            # Update bias
            model['biases'][i] += learning_rate * gradient_direction
        
        return model