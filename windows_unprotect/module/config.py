#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - Configuration file - config.py version 1.0

This module is the configuration file. You need to configure the variable to modify the main core of the tools.
You can find the following option to configure:

- Color: Print the color of the result of a function
- Yara Rules: configure the path for all the yararule needed
- Global list of specific strings:
      - file_strings: file that contains the list of anti-debugger API
      - lolbin: file that contains the list of lolbin used by malware
      - userdb: Peid signature
- VirusTotal API Key

"""
import yara
import os
from pathlib import Path


# VARIABLES TO CHANGE
#############################################################################
# Put your Virustotalcd  API Key
APIKEY = ""

# Add your own yara rules file if you want
USER_RULES = "user_rules.yar"
#############################################################################

# authorship information
__author__ = "Thomas Roccia | @fr0gger_"
__copyright__ = "Unprotect Project"
__credits__ = [""]
__license__ = "APACHE V2.0"
__version__ = "1.1"
__maintainer__ = "@fr0gger"
__email__ = "fr0gger@frogger.cooom"
__status__ = "BlackHat Release"
__asciiart__ = '''
         __ __                 _           _      _____     _
        |  |  |___ ___ ___ ___| |_ ___ ___| |_   |     |___| |_ _ _ ___ ___ ___
        |  |  |   | . |  _| . |  _| -_|  _|  _|  | | | | .'| | | | | .'|  _| -_|
        |_____|_|_|  _|_| |___|_| |___|___|_|    |_|_|_|__,|_|_____|__,|_| |___|
                  |_|
        '''

# Colors config
R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'  # white

try:

    # Get yara-rule and signature directory
    dirsig = os.path.abspath(os.path.dirname(__file__))
    # Yara rules path

    rule_compiler = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/compiler.yar'))
    rule_packer = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/packers.yar'))
    rule_antisb = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/antisb_unprotect.yar'))
    rule_antidbg = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/antidbg_unprotect.yar'))
    rule_antiav = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/antiav_unprotect.yar'))
    rule_procinject = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/procinject_unprotect.yar'))
    rule_findcrypt = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/findcrypt.yar'))
    rule_antimonitoring = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/anti_monitoring.yar'))
    rule_network_evasion = yara.compile(filepath=os.path.join(dirsig, 'yara-rules/network_evasion.yar'))

    # Specific files
    antidbg_api = os.path.join(dirsig, "signature/antidbg.txt")
    lolbin = os.path.join(dirsig, "signature/lolbin.txt")
    userdb = os.path.join(dirsig, "signature/userdb.txt")
    procinj_api = os.path.join(dirsig, "signature/procinj.txt")
    domain_suffixes = os.path.join(dirsig, "signature/domain_suffixes.txt")
    antiav = os.path.join(dirsig, "signature/antiav.txt")

    # User_Rules
    rules_user = yara.compile(filepath=os.path.join(dirsig, "yara-rules/" + USER_RULES))

except IOError as err:
    print err
