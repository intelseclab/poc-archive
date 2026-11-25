#!/usr/bin/env python3
"""Compatibility alias for the canonical one-shot at ../exploit.py."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
os.execv(sys.executable, [sys.executable, os.path.join(ROOT, "exploit.py"), *sys.argv[1:]])
