"""
Research Experiments Package for QE-NIDS.
Implements the Leave-One-Attack-Class-Out (LOACO) empirical novelty benchmark.
"""

from .leave_one_out import run_leave_one_out_experiment

__all__ = ["run_leave_one_out_experiment"]
