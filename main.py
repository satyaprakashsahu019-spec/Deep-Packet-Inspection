#!/usr/bin/env python3
"""
Unified entry point for Deep Packet Inspection System.
"""

from __future__ import annotations
import sys
import dpi_engine


def main():
    return dpi_engine.main()


if __name__ == "__main__":
    sys.exit(main())
