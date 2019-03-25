#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - get info about pe - pe_info.py version 1.0

This module get information about the pe file.

"""
import yara

def yarascan(pe, rules):
    try:
        matches = rules.match(pe)
    except ValueError as e:
        print(e)
    if matches:
        return matches
    return
