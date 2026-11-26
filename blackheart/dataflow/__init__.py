"""Whole-program taint/dataflow over Solidity source."""

from .ssa import DataflowResult, Flow, SSAValue, Taint, analyse_source

__all__ = ["DataflowResult", "Flow", "SSAValue", "Taint", "analyse_source"]
