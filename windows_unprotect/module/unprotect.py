#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - main file - unprotect.py version 1.0

This module is the main file of the Unprotect. This fil will call every module of the project for the analysis.


"""
import sys
import pefile
import config

from pe_info import get_info
from pe_info import get_hash
from pe_info import get_meta
from pe_info import get_antidebug
from pe_info import get_procinj
from pe_info import get_sec
from pe_info import get_impfuzzy
from pe_info import get_mmh
from pe_info import get_richhash
from pe_info import check_tls
from pe_info import display_resources

from strings import get_strings

from packer import get_peid
from packer import possible_packing

from antivm import get_vm
from antivm import antivm_inst
from antiav import get_av_evasion
from antiav import get_pesize
from antiav import get_crt
from antiav import get_av_strings

from disas import garbage_byte
from disas import fake_jump
from disas import flow_redirect
from disas import nop_seq
from disas import check_iat

from network_evasion import get_url, get_ip
from prettytable import PrettyTable

from utils import yarascan
from virusapi import get_vt
from tabulate import tabulate


def help():
    print config.__asciiart__
    print "\t\t" + config.__copyright__ + " | " + config.__author__
    print "\t\t\tUnprotect malware for the mass"
    print "\t\t\t Current status: " + config.__status__
    print config.C + "\n[*] Usage: python unprotect.py malware.exe\n"


def main(exefile):
    if len(sys.argv) == 1 or len(sys.argv) >= 3:
        help()
        exit(0)

    if len(sys.argv) == 2 and sys.argv[1] == "-h" or sys.argv[1] == "--help":
        help()
        exit(0)

    if len(sys.argv) == 2:

        print config.__asciiart__
        print "\t\t" + config.__copyright__ + " | " + config.__author__
        print "\t\t\tUnprotect malware for the mass"
        print "\t\t\t Current status: " + config.__status__

        try:
            exe = pefile.PE(exefile)
        except OSError as e:
            print(e)
            sys.exit()
        except pefile.PEFormatError as e:
            print config.R + "[-] PEFormatError: %s" % e.value
            print config.R + "[!] The file is not a valid PE"
            sys.exit()


        # bar = IncrementalBar('Grabbing Data on the PE', max=20)
        #
        # print text1
        # for i in range(20):
        #     #print i
        #     # Do some work
        #     #print text1
        #     #strings_list, decoded_strings = get_strings(exefile)
        #     #time.sleep(0.2)
        #     bar.next()
        # bar.finish()

        strings_list, decoded_strings = get_strings(exefile)

        concatenate_strings = str(strings_list + decoded_strings)

        print "\nPE Summary"
        print "-" * 80

        ftype, fname, fsize, tsdate, dll, nsec = get_info(exe, exefile)

        print config.C + "File type:\t " + config.W + "%s" % ftype
        print config.C + "File name:\t " + config.W + "%s" % fname
        print config.C + "File size:\t " + config.W + "%s Bytes" % fsize
        print config.C + "Compile time:\t " + config.W + "%s" % tsdate
        print config.C + "Entry point:\t " + config.W + "0x%.8x" % exe.OPTIONAL_HEADER.AddressOfEntryPoint
        print config.C + "Image base:\t " + config.W + "0x%.8x" % exe.OPTIONAL_HEADER.ImageBase

        md5, sha1, ih, hashdeep, sha2, sha5 = get_hash(exe, exefile)
        print config.C + "Hash MD5:\t " + config.W + "%s" % md5
        # print config.C + "Hash SHA1:\t " + config.W + "%s" % sha1
        print config.C + "Hash SHA2:\t " + config.W + "%s" % sha2
        # print config.C + "Hash SHA5:\t " + config.W + "%s" % sha5
        print config.C + "Import hash:\t " + config.W + "%s" % ih
        print config.C + "Ssdeep:\t\t " + config.W + "%s" % hashdeep

        impfuzzy = get_impfuzzy(exefile)
        print config.C + "ImpFuzzy:\t " + config.W + "%s" % impfuzzy

        mmh = get_mmh(exefile)
        print config.C + "MinHash:\t " + config.W + "%s" % mmh

        xored_richhash, clear_richhash = get_richhash(exe, exefile)
        print config.C + "Xored RicHash:\t " + config.W + "%s" % xored_richhash
        print config.C + "Clear RicHash:\t " + config.W + "%s" % clear_richhash

        print "\nVirus Total Report"
        print "-" * 80

        try:
            resp_code, scan_date, permalink, positives, total = get_vt(config.APIKEY, exefile)

            if resp_code == 1:
                print "Scan date:\t %s" % scan_date
                print("Detection:\t %s/%s" % (positives, total))
                print "Permalink:\t %s" % permalink
            else:
                print config.R + "[-]" + config.W + " No Virus Total report available!"

        except IOError:
            print config.R + "[-]" + config.W + " Virus Total not available or no connexion found!"
            pass

        print "\nExploit Mitigation"
        print "-" * 80
        aslr_check, dep_check, seh_check, cfg_check = get_sec(exe)
        if aslr_check:
            print config.G + "[+]" + config.W + " ASLR enabled"
        else:
            print config.R + "[-]" + config.W + " ASLR not enabled"

        if dep_check:
            print config.G + "[+]" + config.W + " DEP enabled"
        else:
            print config.R + "[-]" + config.W + " DEP not enabled"

        if seh_check:
            print config.G + "[+]" + config.W + " SEH enabled"
        else:
            print config.R + "[-]" + config.W + " SEH not enabled"

        if cfg_check:
            print config.G + "[+]" + config.W + " CFG enabled"
        else:
            print config.R + "[-]" + config.W + " CFG not enabled"

        print "\nFile Metadata"
        print "-" * 80
        result = get_meta(exe)
        if not bool(result):
            print config.R + "[-]" + config.W + " PE file has no metadata available!"

        print "\nPacker Detection"
        print "-" * 75
        peid_detect = get_peid(exe)

        if peid_detect:
            print config.G + "[+]" + config.W + " PEiD detection: %s " % peid_detect
        else:
            print config.R + "[-]" + config.W + " No PEiD detection!"

        pepack, emptysec, enaddr, vbsecaddr, ensecaddr, entaddr = possible_packing(exe)
        if bool(pepack):
            print config.G + "[+]" + config.W + " Sections entropy is high, the binary is possibly packed!"

        if bool(emptysec):
            print config.G + "[+]" + config.W + " Non-ascii or empty section names detected"

        if enaddr > entaddr:
            print config.G + "[+]" + config.W + " Entry point is outside the .code section, the binary is possibly packed!"

        print config.G + "[+]" + config.W + " PE Sections:"

        x = PrettyTable()
        x.field_names = ["Section Name", "Virtual Address", "Size", "Entropy"]

        for section in exe.sections:
            x.add_row([section.Name.strip(), "0x" + str(section.VirtualAddress), "0x" + str(section.Misc_VirtualSize), section.get_entropy()])

            #print("    Section Name: %s\t\t" % section.Name.strip() + "Virtual Address: 0x%.8x \t\t" % section.VirtualAddress \
            #      + "Size: 0x%.8x \t\t" % section.Misc_VirtualSize + "Entropy: %f" % section.get_entropy())

        print x

        matches = yarascan(exefile, config.rule_packer)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches

        print "\nAnti-Sandboxing Tricks"
        print "-" * 80
        trk = get_vm(exefile)

        if trk:
            print config.G + "[+]" + config.W + " Anti-sandboxing tricks detected: %s " % str(trk)
        else:
            print config.R + "[-]" + config.W + " No anti-sandboxing tricks detected!"

        count = antivm_inst(exe)
        if count == 0:
            print config.R + "[-]" + config.W + " No antivm instruction detected!"

        else:
            print config.G + "[+]" + config.W + " Number of antivm instruction detected (SIDT, SLDT, CPUID, STR): %s" % count

        matches = yarascan(exefile, config.rule_antisb)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches

        print "\nAnti-Debugging Tricks"
        print "-" * 80

        tlscallback = check_tls(exe)

        if tlscallback:
            print(config.G + "[+]" + config.W + " TLS Callback found at: 0x%x" % tlscallback)

        dbgmatches = get_antidebug(exe, config.antidbg_api)

        if dbgmatches:
            print config.G + "[+]" + config.W + " Anti-debugging API detected: "
            print tabulate(dbgmatches, headers=['Address', 'API']) + "\n"
        else:
            print config.R + "[-]" + config.W + " No Anti-debugging API detected!"

        matches = yarascan(exefile, config.rule_antidbg)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches

        print "\nAnti-Virus Evasion Tricks"
        print "-" * 80

        try:
            errorlog, result1, result2, originalname = get_av_evasion(exe, config.lolbin)
        except(AttributeError, RuntimeError, TypeError, NameError):
            errorlog = False
            result1 = False
            result2 = False
            originalname = False

        avdetected = get_av_strings(strings_list, config.antiav)

        if not bool(errorlog):
            if result1 is True:
                print config.G + "[+]" + config.W + " The filename extension is not valid. It might be used to trick the AV!"
                print config.G + "[+]" + config.W + " Original filename: %s " % originalname
            else:
                print config.R + "[-]" + config.W + " No trick with the extension!"

            if result2 is True:
                print config.G + "[+]" + config.W + " Lolbin filename detected! Possible AV evasion trick!"
                print config.G + "[+]" + config.W + " Original filename: %s " % originalname

            else:
                print config.R + "[-]" + config.W + " No Lolbin detected!"

        else:
            print config.R + "[-]" + config.W + " No AV evasion tricks detected!"

        if avdetected:
            print config.G + "[+]" + config.W + " Potential AV targeted by the sample:"
            for av in avdetected:
                print "\t" + av
        else:
            print config.R + "[-]" + config.W + " No strings related to AV detected!"

        bigfile = get_pesize(exefile)
        if bigfile:
            print config.G + "[+]" + config.W + " The PE file is bigger than 5MB! Possible AV evasion trick!"

        try:
            get_crt(exefile)
        except:
            pass

        matches = yarascan(exefile, config.rule_antiav)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches

        print "\nAnti-Disassembling Tricks"
        print "-" * 80
        count = garbage_byte(exe)
        if count == 0:
            print config.R + "[-]" + config.W + " No garbage byte detected!"
        else:
            print config.G + "[+]" + config.W + " Number of potential garbage byte detected: " + config.R + "%s" % count

        count = fake_jump(exe)
        if count == 0:
            print config.R + "[-]" + config.W + " No fake jump detected!"
        else:
            print config.G + "[+]" + config.W + " Number of potential fake jump detected: " + config.R + "%s" % count

        count = flow_redirect(exe)
        if count == 0:
            print config.R + "[-]" + config.W + " No flow redirection detected"
        else:
            print config.G + "[+]" + config.W + " Number of potential flow redirection detected: " + config.R + "%s" % count

        count = nop_seq(exe)
        if count == 0:
            print config.R + "[-]" + config.W + " No nop sequence detected"
        else:
            print config.G + "[+]" + config.W + " Nop sequence detected: " + config.R + "%s" % count

        iatcount, iatlow = check_iat(exe)

        # print iatcount
        if iatcount < 5:
            print config.G + "[+]" + config.W + " IAT contains less than 5 imports. Possibly packed or dynamically called!"

        if iatcount == 0:
            print config.G + "[+]" + config.W + " IAT is empty! Stealth import of Windows API detected!"
        try:
            if "loadlibrarya" in iatlow or "loadlibraryw" in iatlow or "loadlibraryexa" in iatlow or "loadlibraryexw" in iatlow and "getprocaddress":
                print config.G + "[+]" + config.W + " Possible function call obfuscation! LoadLibrary and GetProcAddress found in IAT!"
        except TypeError:
            pass

        print "\nProcess Injection Tricks"
        print "-" * 80
        dbgmatches = get_procinj(exe, config.procinj_api)

        if dbgmatches:
            print config.G + "[+]" + config.W + " Process injection API detected: "
            #for x in dbgmatches:
            #    result = x[0] + ' ' + x[1]
            #    print "\t" + result
            print tabulate(dbgmatches, headers=['Address', 'API']) + "\n"
        else:
            print config.R + "[-]" + config.W + " No process injection API detected!"

        matches = yarascan(exefile, config.rule_procinject)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches

        print "\nObfuscation, Data Encoding"
        print "-" * 80
        matches = yarascan(exefile, config.rule_findcrypt)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches

        else:
            print config.R + "[-] " + config.W + "No obfuscation detected!"

        if decoded_strings:
            print config.R + "[+] " + config.W + "FLOSS decoded strings:"
            # print decoded_strings
            for i in decoded_strings:
                #if i == "AU3!":
                    #decoded_strings.append("AUTO IT Script")
                print "\t" + i
            #print tabulate(decoded_strings, headers=['Strings', 'Detection'])

        print "\nAnti-Monitoring Tricks"
        print "-" * 80
        matches = yarascan(exefile, config.rule_antimonitoring)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches

        else:
            print config.R + "[-] " + config.W + "No anti-monitoring tricks detected!"

        print "\nNetwork Evasion Tricks"
        print "-" * 80

        uniq_iplist = get_ip(concatenate_strings)
        uniq_urllist = get_url(concatenate_strings)

        if uniq_iplist:

            print config.G + "[+] " + config.W + "IP addresses found!"
            print tabulate(uniq_iplist, headers=['IP', 'Status', 'Location'])
            print "\n"
        else:
            print config.R + "[-] " + config.W + "No IP address found"

        if uniq_urllist:
            print config.G + "[+] " + config.W + "Urls found!"
            print tabulate(uniq_urllist, headers=['URLs', 'Fast Flux', 'DGA'])
            print "\n"
        else:
            print config.R + "[-] " + config.W + "No urls found"

        matches = yarascan(exefile, config.rule_network_evasion)
        if matches is not None:
            print config.G + "[+] " + config.W + "Yara detection: %s" % matches




        print "\nAdditional Information"
        print "-" * 80

        res = display_resources(exe)

        if res:
            print config.G + "[+] " + config.W + "Ressources: "
            #print res
            print tabulate(res, headers=['Id', 'Name', 'Size', 'Lang', 'Sublang', 'Type', 'MD5'])
        else:
            print config.R + "[-] " + config.W + "No ressources available"

        # Look for email address
        #print config.G + "[+] " + config.W + "Email address: "
        #for line in concatenate_strings:
        #    if re.match(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', line):
        #        print line


        print "\n"
        print config.C + "All done!\n"


if __name__ == "__main__":
    try:
        exefile = sys.argv[1]
        main(exefile)
    except IndexError:
        print "[!] You must supply a PE file kiddo! Or --help!"
