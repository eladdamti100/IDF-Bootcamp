"""GLASSBOX — explainable process-command attack detector + kill-chain story engine.

Pure-stdlib core (no install needed). Optional transformer/LLM enhancers.
Design invariants:
  1. A global time budget with a deterministic fallback at every AI step.
  2. "When uncertain, benign" — FP costs 2 points, FN costs 0.
  3. The malicious COUNT is never hardcoded; thresholds are calibrated, count-independent.
"""
__all__ = ["normalize", "signatures", "features", "killchain", "verifier", "pipeline"]
