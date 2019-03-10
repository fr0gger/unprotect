"""ssdeep-ftw (SSDEEP - For The Windows) v1.0
A simple python mini-wrapper to use ssdeep on Windows,
progamatically. This is not a robust thing, and merely a
hack to get the work done. Use it at your own risk.

/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <me@c0d.ist> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return. @c0dist
 * ----------------------------------------------------------------------------
 */

---
Tested on:
OS: Windows 7
Python: 2.7
SSDEEP Version: 2.13
"""
import os
from sys import exit
import subprocess
from tempfile import mkstemp
# Importing under new name for clarity.
from re import findall as regex_findall 

__author__ = "c0dist@garage4hackers modified by fr0gger"
__version__ = 1.0

from pathlib import Path, PureWindowsPath

filename = Path("ssdeep-2.13/ssdeep.exe")
SSDEEP_PATH = PureWindowsPath(filename)



# Overwite the path constant, if required.
# SSDEEP_PATH = "C:\\ssdeep-2.13\\ssdeep.exe"
SSDEEP_HEADERS = "ssdeep,1.1--blocksize:hash:hash,filename\n"

class SSFTW:
    """A mini SSDEEP wrapper class for Windows.
    Supported operations:
        - Computing ssdeep hash from a file.
        - Computing ssdeep hash from a string.
        - Comparing two ssdeep hashes.

    TODO: 
        - Comparing two files.
    """
    def __init__(self, path_to_ssdeep):
        """ Exits if provided ssdeep executable does not exists.
        """
        self.ssdeep_exe = path_to_ssdeep
        if not os.path.exists(self.ssdeep_exe):
            print "[-] Exiting."
            exit(1)

    def hash(self, data=""):
        """This function takes the given string and writes it 
        into a temporary file. This file is then passed to 
        `hash_from_file`.

        NOTE: Author couldn't find any option to compute ssdeep 
        hash from a string using command line, hence the hack.

        @params data - str - data to compute hash of.

        :returns ssdeep hash (str) if success, else None.
        """
        try:
            fd, tmpfile = mkstemp()
            with open(tmpfile, "w") as tmp:
                tmp.write(data)
            return self.hash_from_file(tmpfile)
        except Exception as e:
            print "[-] Some error. %s" % str(e)
            return None
        finally:
            os.close(fd)
            os.remove(tmpfile)
    
    def hash_from_file(self, filepath):
        """ This function computes hash from given file. In case of 
        any error, it returns None. Otherwise, the ssdeep hash of the
        file is returned as a string. This s also internally called
        by `hash`.

        @params filepath - str - Path to the file.

        :returns ssdeep hash (str) if success, else None.
        """
        filepath = os.path.abspath(filepath)
        if os.path.exists(filepath):
            if not os.path.isfile(filepath):
                print "[-] %s is not a file." % filepath
                return None
            
            # "ssdeep_exe -s -c filepath"
            cmd = [self.ssdeep_exe, "-s", "-c", filepath]
        
            # Executing finally.
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            output, err = process.communicate()
            status = process.returncode
        
            if status == 0:
                return self.parse_output(output)
            else:
                print err
        else:
            print "[-] %s does not exists." % filepath
        return None

    def compare(self, hash1, hash2):
        """Compares two ssdeep hashes. Author couldn't find a way
        to find the ratio by providing hashes as strings via the ssdeep 
        command line tool. Hence, the hack. Please, suggest, if any other way.

        However, you can write your two hashes to file (in a specific
        format that ssdeep understands) and then use "-x" switch to
        compare hashes stored in those two files. Which is what this code does.

        @params: hash1 - str - ssdeep hash.
        @params: hash2 - str - ssdeep hash.

        :returns int if command succeeds, else None.
        """
        try:
            files = []
            for i in xrange(2):
                d = {}
                d["fd"], d["file"] = mkstemp()
                files.append(d)
                with open(d["file"], "w") as tmp:
                    tmp.write(SSDEEP_HEADERS)
                    line2 = "%s,\"temp%d\"\n" % (hash1, i)
                    tmp.write(line2)

            return self.compare_files(files[0]["file"],
                                     files[1]["file"],
                                     hashfile=True)
        except Exception as e:
            print "[-] Some error. %s" % str(e)
            return None
        finally:
            for i in xrange(2):
                os.close(files[i]["fd"])
                os.remove(files[i]["file"])

    def compare_files(self, file1, file2, hashfile=True):
        """ This function can only compare ssdeep hash files, for now.
        The possibility to compare two normal files will be added soon. 
        Hence, `hashfile` has been kept True by default.

        @params: file1 - str - Path to file 1
        @params: file2 - str - Path to file 1=2
        @params: hashfile - boolean - If the provided files are
                                    ssdeep hash files.

        :returns int if command succeeds, else None.
        """
        file1 = os.path.abspath(file1)
        file2 = os.path.abspath(file2)
        
        if hashfile:
            # Logic to compute ratio for two hash files.
            cmd = [self.ssdeep_exe, "-s", "-x", file1, file2]
            # Executing finally.
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            output, err = process.communicate()
            status = process.returncode
        
            if status == 0:
                return self.parse_output(output, mode="ratio")
            else:
                print err
        
    def parse_output(self, data, mode="hash"):
        """ This function parses the output produced by ssdeep
        command. This is dirty parsing, but works as intended
        (at least for now).

        @params data - str - The output of ssdeep command.
        @params mode - str - Where did you get the output from?
                           Accepts "hash" or "ratio".

        :returns str/int. ssdeep hash or ratio from the output.
        """
        result = None
        if mode == "hash":
            l = [line for line in data.splitlines() if line][-1]
            result = l.split(",")[0]        
            return result
        elif mode == "ratio":
            l = [line for line in data.splitlines() if line][0]
            # Using regex to find the pattern (<ratio-int>) in the output
            result = int(regex_findall("\(\d{1,3}", l)[0].split("(")[1])
        return result

if __name__ == "__main__":
    #TODO: Command line options can be added, but not needed.
    print "[+] Use it as a module"
