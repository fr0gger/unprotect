#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - VT API - virusapi.py version 1.0

This module get VirusTotal report.

"""

import hashlib
import json
import requests

def get_vt(api_key, filepe):
    hash_md5 = hashlib.md5()
    with open(filepe, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
             hash_md5.update(chunk)
    hmd5 = hash_md5.hexdigest()

    params = {'apikey': api_key, 'resource': hmd5}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  My Python requests library example client or username"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    response0 = response.json()
    response2 = json.dumps(response0)
    load_r = json.loads(response2)
    resp_code = load_r['response_code']

    if resp_code == 1:
        scan_date = load_r['scan_date']
        permalink = load_r['permalink']
        positives = load_r['positives']
        total = load_r['total']
    else:
        scan_date = 0
        permalink = 0
        positives = 0
        total = 0

    return resp_code, scan_date, permalink, positives, total
