#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - get info about pe - pe_info.py version 1.0

This module get information about the pe file.

"""
import os
import lief
import config


def get_av_evasion(pe, lolbin):
    listbin = open(lolbin, 'r')
    binl = listbin.readlines()
    # binmatches = []
    result1 = False
    result2 = False
    originalname = 0

    try:
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        if entry[0] == "OriginalFilename":
                            originalname = entry[1].lower()
                            if not originalname.endswith((".exe", ".dll", ".scr", ".efi", ".ocx", ".sys", ".bin")):
                                result1 = True

                            for binar in binl:
                                # print binar[:-1]
                                if originalname == binar[:-1]:
                                    result2 = True

                            errorlog = False
                            return errorlog, result1, result2, originalname

    except (AttributeError, RuntimeError, TypeError, NameError):
        errorlog = True
        return errorlog, result1, result2, originalname


def get_pesize(pe):
    fsize = os.path.getsize(pe)
    if fsize > 5000000:
        return True
    else:
        return False


def get_crt(pe):
    bin = lief.parse(pe)
    table = []
    for crt in bin.signature.certificates:
        table.append(crt)

    if crt:
        print config.G + "[+]" + config.W + " The file is signed, you may check the following certificate!"
        print crt
    else:
        print config.R + "[-]" + config.W + " No certificate found!"


def get_av_strings(stringlst, antiavstrings):
    listav = open(antiavstrings, 'r')
    listread = listav.readlines()
    avdetected = []

    for line in stringlst:
        line2 = line.lower()

        if any(line2 in s.lower() for s in listread):
            avdetected.append(line)

    return avdetected
