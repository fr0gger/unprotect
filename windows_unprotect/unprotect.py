#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - main file - unprotect.py version 1.0

This module is the main file of the Unprotect. This fil will call every module of the project for the analysis.


"""
import sys
import pefile
import re
import module.config

from module.pe_info import get_info
from module.pe_info import get_hash
from module.pe_info import get_meta
from module.pe_info import get_antidebug
from module.pe_info import get_procinj
from module.pe_info import get_sec
#from module.pe_info import get_impfuzzy
from module.pe_info import get_mmh
from module.pe_info import get_richhash
from module.pe_info import check_tls
from module.pe_info import display_resources

from module.strings import get_strings

from module.packer import get_peid
from module.packer import possible_packing

from module.antivm import get_vm
from module.antivm import antivm_inst
from module.antiav import get_av_evasion
from module.antiav import get_pesize
from module.antiav import get_crt
from module.antiav import get_av_strings

from module.disas import garbage_byte
from module.disas import fake_jump
from module.disas import flow_redirect
from module.disas import nop_seq
from module.disas import check_iat

from module.network_evasion import get_url, get_ip

from prettytable import PrettyTable

from module.utils import yarascan
from module.virusapi import get_vt
from tabulate import tabulate


def help():
    print module.config.__asciiart__
    print "\t\t" + module.config.__copyright__ + " | " + module.config.__author__
    print "\t\t\t      " + module.config.__status__
    print  "\n[*] Usage: python unprotect.py malware.exe\n"


def main(exefile):
    if len(sys.argv) == 1 or len(sys.argv) >= 3:
        help()
        exit(0)

    if len(sys.argv) == 2 and sys.argv[1] == "-h" or sys.argv[1] == "--help":
        help()
        exit(0)
		
    if len(sys.argv) == 2:

        print module.config.__asciiart__
        print "\t\t" + module.config.__copyright__ + " | " + module.config.__author__
        # print "\t\t\tUnprotect malware for the mass"
        print "\t\t\t      " + module.config.__status__

        try:
            exe = pefile.PE(exefile)
        except OSError as e:
            print(e)
            sys.exit()
        except pefile.PEFormatError as e:
            print  "[-] PEFormatError: %s" % e.value
            print  "[!] The file is not a valid PE"
            sys.exit()

        strings_list, decoded_strings = get_strings(exefile)

        concatenate_strings = strings_list + decoded_strings

        print "\nPE Summary"
        print "-" * 80

        fname, fsize, tsdate, dll, nsec = get_info(exe, exefile)

        #print  "File type:\t %s" % ftype
        print  "File name:\t %s" % fname
        print  "File size:\t %s Bytes" % fsize
        print  "Compile time:\t %s" % tsdate
        print  "Entry point:\t 0x%.8x" % exe.OPTIONAL_HEADER.AddressOfEntryPoint
        print  "Image base:\t 0x%.8x" % exe.OPTIONAL_HEADER.ImageBase

        md5, sha1, ih, hashdeep, sha2, sha5 = get_hash(exe, exefile)
        print  "Hash MD5:\t %s" % md5
        # print  "Hash SHA1:\t %s" % sha1
        print  "Hash SHA2:\t %s" % sha2
        # print  "Hash SHA5:\t %s" % sha5
        print  "Import hash:\t %s" % ih
        print  "Ssdeep:\t\t %s" % hashdeep

        #impfuzzy = get_impfuzzy(exefile)
        #print  "ImpFuzzy:\t %s" % impfuzzy

        mmh = get_mmh(exefile)
        print  "MinHash:\t %s" % mmh

        xored_richhash, clear_richhash = get_richhash(exe, exefile)
        print  "Xored RicHash:\t %s" % xored_richhash
        print  "Clear RicHash:\t %s" % clear_richhash

        print "\nVirus Total Report"
        print "-" * 80

        try:
            resp_code, scan_date, permalink, positives, total = get_vt(module.config.APIKEY, exefile)

            if resp_code == 1:
                print "Scan date:\t %s" % scan_date
                print("Detection:\t %s/%s" % (positives, total))
                print "Permalink:\t %s" % permalink
            else:
                print  "[-] No Virus Total report available!"

        except IOError:
            print  "[-] Virus Total not available or no connexion found!"
            pass

        print "\nExploit Mitigation"
        print "-" * 80
        aslr_check, dep_check, seh_check, cfg_check = get_sec(exe)
        if aslr_check:
            print "[+] ASLR enabled"
        else:
            print  "[-] ASLR not enabled"

        if dep_check:
            print "[+] DEP enabled"
        else:
            print  "[-] DEP not enabled"

        if seh_check:
            print "[+] SEH enabled"
        else:
            print  "[-] SEH not enabled"

        if cfg_check:
            print "[+] CFG enabled"
        else:
            print  "[-] CFG not enabled"

        print "\nFile Metadata"
        print "-" * 80
        result = get_meta(exe)
        if not bool(result):
            print  "[-] PE file has no metadata available!"

        print "\nPacker Detection"
        print "-" * 75
        peid_detect = get_peid(exe)

        if peid_detect:
            print "[+] PEiD detection: %s " % peid_detect
        else:
            print  "[-] No PEiD detection!"

        pepack, emptysec, enaddr, vbsecaddr, ensecaddr, entaddr = possible_packing(exe)
        if bool(pepack):
            print "[+] Sections entropy is high, the binary is possibly packed!"

        if bool(emptysec):
            print "[+] Non-ascii or empty section names detected"

        if enaddr > entaddr:
            print "[+] Entry point is outside the .code section, the binary is possibly packed!"

        print "[+] PE Sections:"

        x = PrettyTable()
        x.field_names = ["Section Name", "Virtual Address", "Size", "Entropy"]

        for section in exe.sections:
            x.add_row([section.Name.strip(), "0x" + str(section.VirtualAddress), "0x" + str(section.Misc_VirtualSize), section.get_entropy()])
        print x

        matches = yarascan(exefile, module.config.rule_packer)
        if matches is not None:
            print "[+] Yara detection: %s" % matches

        print "\nAnti-Sandboxing Tricks"
        print "-" * 80
        trk = get_vm(exefile)

        if trk:
            print "[+] Anti-sandboxing tricks detected: %s " % str(trk)
        else:
            print  "[-] No anti-sandboxing tricks detected!"

        count = antivm_inst(exe)
        if count == 0:
            print  "[-] No antivm instruction detected!"

        else:
            print "[+] Number of antivm instruction detected (SIDT, SLDT, CPUID, STR): %s" % count

        matches = yarascan(exefile, module.config.rule_antisb)
        if matches is not None:
            print "[+] Yara detection: %s" % matches

        print "\nAnti-Debugging Tricks"
        print "-" * 80

        tlscallback = check_tls(exe)

        if tlscallback:
            print("[+] TLS Callback found at: 0x%x" % tlscallback)

        dbgmatches = get_antidebug(exe, module.config.antidbg_api)

        if dbgmatches:
            print "[+] Anti-debugging API detected: "
            print tabulate(dbgmatches, headers=['Address', 'API']) + "\n"
        else:
            print  "[-] No Anti-debugging API detected!"

        matches = yarascan(exefile, module.config.rule_antidbg)
        if matches is not None:
            print "[+] Yara detection: %s" % matches

        print "\nAnti-Virus Evasion Tricks"
        print "-" * 80

        try:
            errorlog, result1, result2, originalname = get_av_evasion(exe, module.config.lolbin)
        except(AttributeError, RuntimeError, TypeError, NameError):
            errorlog = False
            result1 = False
            result2 = False
            originalname = False

        avdetected = get_av_strings(strings_list, module.config.antiav)

        if not bool(errorlog):
            if result1 is True:
                print "[+] The filename extension is not valid. It might be used to trick the AV!"
                print "[+] Original filename: %s " % originalname
            else:
                print  "[-] No trick with the extension!"

            if result2 is True:
                print "[+] Lolbin filename detected! Possible AV evasion trick!"
                print "[+] Original filename: %s " % originalname

            else:
                print  "[-] No Lolbin detected!"

        else:
            print  "[-] No AV evasion tricks detected!"

        if avdetected:
            print "[+] Potential AV targeted by the sample:"
            for av in avdetected:
                print "\t" + av
        else:
            print  "[-] No strings related to AV detected!"

        bigfile = get_pesize(exefile)
        if bigfile:
            print "[+] The PE file is bigger than 5MB! Possible AV evasion trick!"

        try:
            get_crt(exefile)
        except:
            pass

        matches = yarascan(exefile, module.config.rule_antiav)
        if matches is not None:
            print "[+] Yara detection: %s" % matches

        print "\nAnti-Disassembling Tricks"
        print "-" * 80
        count = garbage_byte(exe)
        if count == 0:
            print  "[-] No garbage byte detected!"
        else:
            print "[+] Number of potential garbage byte detected: " +  "%s" % count

        count = fake_jump(exe)
        if count == 0:
            print  "[-] No fake jump detected!"
        else:
            print "[+] Number of potential fake jump detected: " +  "%s" % count

        count = flow_redirect(exe)
        if count == 0:
            print  "[-] No flow redirection detected"
        else:
            print "[+] Number of potential flow redirection detected: " +  "%s" % count

        count = nop_seq(exe)
        if count == 0:
            print  "[-] No nop sequence detected"
        else:
            print "[+] Nop sequence detected: " +  "%s" % count

        iatcount, iatlow = check_iat(exe)

        # print iatcount
        if iatcount < 5:
            print "[+] IAT contains less than 5 imports. Possibly packed or dynamically called!"

        if iatcount == 0:
            print "[+] IAT is empty! Stealth import of Windows API detected!"
        try:
            if "loadlibrarya" in iatlow or "loadlibraryw" in iatlow or "loadlibraryexa" in iatlow or "loadlibraryexw" in iatlow and "getprocaddress":
                print "[+] Possible function call obfuscation! LoadLibrary and GetProcAddress found in IAT!"
        except TypeError:
            pass

        print "\nProcess Injection Tricks"
        print "-" * 80
        dbgmatches = get_procinj(exe, module.config.procinj_api)

        if dbgmatches:
            print "[+] Process injection API detected: "
            print tabulate(dbgmatches, headers=['Address', 'API']) + "\n"
        else:
            print  "[-] No process injection API detected!"

        matches = yarascan(exefile, module.config.rule_procinject)
        if matches is not None:
            print "[+] Yara detection: %s" % matches

        print "\nObfuscation, Data Encoding"
        print "-" * 80
        matches = yarascan(exefile, module.config.rule_findcrypt)
        if matches is not None:
            print "[+] Yara detection: %s" % matches

        else:
            print  "[-] No obfuscation detected!"

        if decoded_strings:
            print  "[+] FLOSS decoded strings:"
            # print decoded_strings
            for i in decoded_strings:
                print "\t" + i

        print "\nAnti-Monitoring Tricks"
        print "-" * 80
        matches = yarascan(exefile, module.config.rule_antimonitoring)
        if matches is not None:
            print "[+] Yara detection: %s" % matches

        else:
            print  "[-] No anti-monitoring tricks detected!"

        print "\nNetwork Evasion Tricks"
        print "-" * 80

        uniq_iplist = get_ip(str(concatenate_strings))
        uniq_urllist = get_url(str(concatenate_strings))

        if uniq_iplist:

            print "[+] IP addresses found!"
            print tabulate(uniq_iplist, headers=['IP', 'Status', 'Location'])
            print "\n"
        else:
            print  "[-] No IP address found"

        if uniq_urllist:
            print "[+] Urls found!"
            print tabulate(uniq_urllist, headers=['URLs', 'Fast Flux', 'DGA'])
            print "\n"
        else:
            print  "[-] No urls found"

        matches = yarascan(exefile, module.config.rule_network_evasion)
        if matches is not None:
            print "[+] Yara detection: %s" % matches


        print "\nAdditional Information"
        print "-" * 80

        res = display_resources(exe)

        if res:
            print "[+] Ressources: "
            print tabulate(res, headers=['Id', 'Name', 'Size', 'Lang', 'Sublang', 'MD5'])
        else:
            print  "[-] No ressources available"

        BTC = []
        MNR = []
        ETH = []
        email = []

        for line in concatenate_strings:
            if re.match(r'^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$', line):
                BTC.append(line)
            elif re.match(r'^4([0-9]|[A-B])(.){93}', line):
                MNR.append(line)
            elif re.match(r'^0x[a-fA-F0-9]{40}$', line):
                ETH.append(line)
            elif re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', line):
                email.append(line)

        if BTC:
            print "\n[+] Bitcoin regex matching: "
            for i in BTC:
                print i

        if MNR:
            print "\n[+] Monero regex matching: "
            for i in MNR:
                print i

        if ETH:
            print "\n[+] Ethereum regex matching: "
            for i in ETH:
                print i

        if email:
            print "\n[+] Email regex matching: "
            for i in email:
                print i

        # matches = yarascan(exefile, module.config.rules_user)
        # if matches is not None:
        #    print "\n[+] Matching from user's Yara rules: %s" % matches

        print "\n"
        print  "All done!\n"


if __name__ == "__main__":
    try:
        exefile = sys.argv[1]
        main(exefile)
    except IndexError:
        print "[!] You must supply a PE file kiddo! Or --help!"
