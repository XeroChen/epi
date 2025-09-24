"""
Generalizer Package

This package provides generalization classes for API endpoint discovery.
It contains different strategies for generalizing HTTP messages:

- Generalizer: Abstract base class defining the interface
- AdaptiveGeneralizer: Adaptive pattern detection and semantic generalization
- DrainGeneralizer: Drain3-based template mining with enhanced masking
"""

from .base import Generalizer
from .adaptive import AdaptiveGeneralizer
from .drain import DrainGeneralizer

__all__ = ['Generalizer', 'AdaptiveGeneralizer', 'DrainGeneralizer']