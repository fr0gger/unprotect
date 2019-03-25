#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - get info about pe - pe_info.py version 1.0

This module get information about the pe file.

"""
import datetime
import hashlib
import os
import ssdeep
import magic
import pyimpfuzzy
import mmh3
import re
import math
import numpy as np
import copy
import pefile
from tabulate import tabulate

res = []

# Get summary PE info
def get_info(pe, filename):
    ftype = magic.from_file(filename)
    fname = os.path.basename(filename)
    fsize = os.path.getsize(filename)
    dll = pe.FILE_HEADER.IMAGE_FILE_DLL
    nsec = pe.FILE_HEADER.NumberOfSections
    tstamp = pe.FILE_HEADER.TimeDateStamp
    try:
        """ return date """
        tsdate = datetime.datetime.fromtimestamp(tstamp)
    except:
        """ return timestamp """
        tsdate = str(tstamp) + " [Invalid date]"
    return ftype, fname, fsize, tsdate, dll, nsec


# Get hashes from input PE
def get_hash(pe, filename):
    # Import Hash
    ih = pe.get_imphash()
    fh = open(filename, 'rb')
    m = hashlib.md5()
    s = hashlib.sha1()
    s2 = hashlib.sha256()
    s5 = hashlib.sha512()

    while True:
        data = fh.read(8192)
        if not data:
            break

        m.update(data)
        s.update(data)
        s2.update(data)
        s5.update(data)

    md5 = m.hexdigest()
    sha1 = s.hexdigest()
    sha2 = s2.hexdigest()
    sha5 = s5.hexdigest()

    hashdeep = ssdeep.hash_from_file(filename)
    return md5, sha1, ih, hashdeep, sha2, sha5


# Get Metadata
def get_meta(pe):
    try:
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        print "%s:\t      %s" % (entry[0], entry[1])
                        if entry[0] == "OriginalFilename":
                            originalname = entry[1]
            if fileinfo.Key == 'VarFileInfo':
                for var in fileinfo.Var:
                    print "%s:\t    %s" % var.entry.items()[0]
    except (AttributeError, RuntimeError, TypeError, NameError):
        return False
    return True


def get_antidebug(pe, antidbg_api):
    antidbgs = open(antidbg_api, 'r')
    dbgmatches = []
    line = antidbgs.readlines()
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for antidbg in line:
                for imp in entry.imports:
                    formated = antidbg[:-1]
                    if imp.name == formated:
                        # print '\t', hex(imp.address), imp.name
                        iatdb = hex(imp.address), imp.name
                        dbgmatches.append(iatdb)
    except:
        pass
    return dbgmatches


def get_sec(pe):
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    aslr_check = bool(pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    dep_check = bool(pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    seh_check = bool(pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
    cfg_check = bool(pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    return aslr_check, dep_check, seh_check, cfg_check


def get_procinj(pe, antidbg_api):
    antidbgs = open(antidbg_api, 'r')
    dbgmatches = []
    line = antidbgs.readlines()
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for antidbg in line:
                for imp in entry.imports:
                    formated = antidbg[:-1]
                    if imp.name == formated:
                        # print '\t', hex(imp.address), imp.name
                        iatdb = hex(imp.address), imp.name
                        dbgmatches.append(iatdb)
    except:
        pass

    return dbgmatches


def get_impfuzzy(filename):
    impfuzzy = pyimpfuzzy.get_impfuzzy(filename)
    return impfuzzy


def get_mmh(filename):
    minhash = mmh3.hash(filename)
    return minhash


def get_richhash(pe, filename):
    content = ""
    dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if dotnet.VirtualAddress == 0 and dotnet.Size == 0:
        fh = open(filename, "r")
        for i in fh:
            content += i
        fh.close()
    else:
        return "No Rich header available in .NET executable!", "No Rich header available in .NET executable!"
    try:
        xorkey = re.search("\x52\x69\x63\x68....\x00", content).group(0)[4:8]
        dansAnchor = ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(xorkey, "DanS"))
        richStart = re.search(re.escape(dansAnchor), content).start(0)
        richEnd = re.search("Rich" + re.escape(xorkey), content).start(0)

        if richStart < richEnd:
            rhData = content[richStart:richEnd]
        else:
            raise Exception("The Rich header is not properly formated!")

        clearData = ""  # type: str
        for i in range(0, len(rhData)):
            clearData += chr(ord(rhData[i]) ^ ord(xorkey[i % len(xorkey)]))

        xored_richhash = hashlib.sha256(rhData).hexdigest().lower()
        clear_richhash = hashlib.sha256(clearData).hexdigest().lower()

        return xored_richhash, clear_richhash


    except:
        return "No Rich header available", "No Rich header available"


def get_entropy(labels, base=None):
    """ Computes entropy of label distribution. """

    n_labels = len(labels)

    if n_labels <= 1:
        return 0

    value, counts = np.unique(labels, return_counts=True)
    probs = counts / n_labels
    n_classes = np.count_nonzero(probs)

    if n_classes <= 1:
        return 0

    ent = 0.

    # Compute entropy
    base = e if base is None else base
    for i in probs:
        ent -= i * log(i, base)

    return ent


def check_tls(pe):
    """Check if there is a TLS callback"""
    callbacks = []
    if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
            pe.DIRECTORY_ENTRY_TLS and \
            pe.DIRECTORY_ENTRY_TLS.struct and \
            pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
        callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        idx = 0
        while True:
            func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
            if func == 0:
                break
            callbacks.append(func)
            idx += 1
    if len(callbacks) > 0:
        if len(callbacks) == 1:
            return callbacks[0]
        else:
            return callbacks
            # for r in callbacks:
            #    print("\t- 0x%s" % r)
    return False


def resource(pe, level, r, parents):
    """Recursive printing of resources"""
    if hasattr(r, "data"):
        # resource
        offset = r.data.struct.OffsetToData
        size = r.data.struct.Size
        data = pe.get_memory_mapped_image()[offset:offset + size]
        m = hashlib.md5()
        m.update(data)
        result = ("-".join(parents + [str(r.id)]), str(r.name), "%i B" % size, pefile.LANG.get(r.data.lang, 'UNKNOWN'),
                   pefile.get_sublang_name_for_lang(r.data.lang, r.data.sublang), magic.from_buffer(data),
                   m.hexdigest())

        res.append(result)
        # print tabulate(result, headers=['Id', 'Name', 'Size', 'Lang', 'Sublang', 'Type', 'MD5'])

    else:
        # directory
        #try:
        parents = copy.copy(parents)
        if r.id:
            parents.append(str(r.id))
        elif r.name:

            parents.append(r.name.string.decode('utf-8'))

        for r2 in r.directory.entries:
            resource(pe, level + 1, r2, parents)


def display_resources(pe):
    """Display resources"""
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        if (len(pe.DIRECTORY_ENTRY_RESOURCE.entries) > 0):
            for r in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource(pe, 0, r, [])
    #print type(res) #tabulate(res, headers=['Id', 'Name', 'Size', 'Lang', 'Sublang', 'Type', 'MD5'])
    return res


