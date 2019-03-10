#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - get info about pe - pe_info.py version 1.0

This module get information about the pe file.

"""
import peutils
import config
import re


# Peid Detection
def get_peid(pe):
    signatures = peutils.SignatureDatabase(config.userdb)
    matches = signatures.match_all(pe, ep_only=True)
    array = []
    if matches:
        for item in matches:
            # remove duplicate
            if item[0] not in array:
                array.append(item[0])
    return array


def possible_packing(pe):
    packed = peutils.is_probably_packed(pe)
    emptysec = False
    pepack = False

    if packed == 1:
        pepack = True

    # Non-Ascii or empty section name check
    for sec in pe.sections:
        if not re.match("^[.A-Za-z][a-zA-Z]+", sec.Name):
            emptysec = True

    # Entry point check
    enaddr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    vbsecaddr = pe.sections[0].VirtualAddress
    ensecaddr = pe.sections[0].Misc_VirtualSize
    entaddr = vbsecaddr + ensecaddr

    return pepack, emptysec, enaddr, vbsecaddr, ensecaddr, entaddr
