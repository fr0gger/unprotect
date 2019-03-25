#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - Disassembling PE file - disas.py

This module get information about the pe file.

"""

from capstone import *


def loader_pe(pe):
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    data = pe.get_memory_mapped_image()[entry_point:]
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    rdbin = cs.disasm(data, 0x1000)
    return rdbin


def garbage_byte(pe):
    rdbin = loader_pe(pe)
    count = 0
    for i in rdbin:
        if i.mnemonic == "je" or i.mnemonic == "jz" or i.mnemonic == "jmp":
            nextop = next(rdbin)
            if nextop.mnemonic == "push":
                count += 1
    return count


def fake_jump(pe):  # Experimental
    rdbin = loader_pe(pe)
    count = 0

    for i in rdbin:
        # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.mnemonic == "xor" or i.mnemonic == "clc":
            prev = ("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

            nextop = next(rdbin)
            if nextop.mnemonic == "jnz" or nextop.mnemonic == "jnb":
                # print nextop
                print prev
                print("0x%x:\t%s\t%s" % (nextop.address, nextop.mnemonic, nextop.op_str))
                count += 1

    return count


def flow_redirect(pe):
    rdbin = loader_pe(pe)
    count = 0

    for i in rdbin:
        # print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.mnemonic == "push":
            nextop = next(rdbin)
            if nextop.mnemonic == "ret":
                count += 1
    return count


def nop_seq(pe):
    rdbin = loader_pe(pe)
    count = 0
    for i in rdbin:
        if i.mnemonic == "nop":
            try:
                nextop = next(rdbin)
                if nextop.mnemonic == "nop":
                    nextop2 = next(rdbin)

                    if nextop2.mnemonic == "nop":
                        nextop3 = next(rdbin)

                        if nextop3.mnemonic == "nop":
                            nextop4 = next(rdbin)

                            if nextop4.mnemonic == "nop":
                                nextop5 = next(rdbin)
                                count += 1
            except:
                pass
    return count


def check_iat(pe):
    iat = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                iat.append(imp.name)
    except:
        pass
    iatcount = len(iat)

    try:
        iatlow = [x.lower() for x in iat]

    except (AttributeError, RuntimeError, TypeError, NameError):
        iatlow = 0
        pass

    return iatcount, iatlow
