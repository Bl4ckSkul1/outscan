#!/usr/bin/env python3
"""
OutScan — OutSystems Platform Security Scanner

Usage:
    outscan.py -u https://target.outsystems.com
    outscan.py -u https://target.com --deep
    outscan.py -L targets.txt
    outscan.py -u https://target.com --viewname --module-name MyApp
    outscan.py -u https://target.com --all -o report.json --html report.html

Based on original 0-day research on OutSystems Platform Server 11.x.
By Adrian Martinez | HAAK Cybersecurity
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from os_scanner.main import main

if __name__ == "__main__":
    main()
