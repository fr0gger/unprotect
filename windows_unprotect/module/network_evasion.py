#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - get info about pe - pe_info.py version 1.0

This module get information about the pe file.

"""

import re
import subprocess
import config
import requests
from urlparse import urlparse
from geoip import geolite2


def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b <= 255]

        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False


def get_ip(strings_lst):
    ips = re.findall('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', strings_lst)
    uniq_ip = set(ips)

    if uniq_ip:
        # create list to append
        uniq_iplist = map(lambda x: [x], uniq_ip)

        for line in uniq_iplist:
            splitedline = str(line).split('.')
            lastbyte = str(splitedline[-1]).replace("']", "")

            if "127.0.0.1" in line:
                line.append("localhost")
                line.append("NULL")
            elif "127.0.0.0" in line:
                line.append("localhost")
                line.append("NULL")
            elif lastbyte == "0":
                uniq_iplist.remove(line)
            else:
                iptoping = str(line)[1:-1].replace("'", "")
                try:
                    response = subprocess.check_output(['ping', '-c', '1', '%s' % iptoping],
                                                       stderr=subprocess.STDOUT,  # get all output
                                                       universal_newlines=True  # return string not bytes
                                                       )
                    line.append("Up")
                except subprocess.CalledProcessError:
                    response = None
                    line.append("Down")

                try:
                    geoiplist = geolite2.lookup(iptoping)
                    line.append(geoiplist.country)
                except:
                    line.append("NULL")

        for ip in uniq_iplist:
            for i in ip:
                if i[-1] == "0":
                    ip.remove(i)

        uniq_iplist = [x for x in uniq_iplist if x != []]

        return uniq_iplist


def get_url(strings_lst):
    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', strings_lst)
    # filter on doublon urls
    seen_url = set()
    uniq_url = []
    for x in urls:
        if x not in seen_url:
            uniq_url.append(x)
            seen_url.add(x)

    urllist = []

    if uniq_url:
        uniq_urllist = map(lambda x: [x], uniq_url)
        for line in uniq_urllist:
            domain = urlparse(str(line)[1:-1].replace("'", ""))
        return uniq_urllist


def find_hostnames(string):
    valid_hostname_suffixes = map(lambda string: string.strip(), open(config.domain_suffixes))
    valid_hostname_suffixes = set(valid_hostname_suffixes)

    possible_hostnames = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', string)
    valid_hostnames = filter(
        lambda hostname: hostname.split(".")[-1].lower() in valid_hostname_suffixes,
        possible_hostnames
    )
    return valid_hostnames
