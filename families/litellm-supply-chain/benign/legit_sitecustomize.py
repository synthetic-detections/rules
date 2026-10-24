#!/usr/bin/env python3
# benign: a legitimate sitecustomize.py that just sets encoding
import sys
sys.setdefaultencoding = lambda e: None
