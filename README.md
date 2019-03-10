# UNPROTECT [PROJECT]: Unprotect Malware for the Mass
The Unprotect Project is an Open Source project that aims to propose a complete classification about Evasion Techniques to help to understand and analyze a malware. This project is dedicated to Windows PE malware. It is licensed under APACHE License version 2.0.

![logo](LogoUnprotect.png)

The Unprotect Project contains two main parts: 
* A website with a complete database and evasion techniques classification (NB: the new version of the website is still currently in dev but will be disclose once available.  The previous website is still available here but not updated (http://unprotect.tdgt.org/). 
* A python standalone tool to detect evasion technique in a specific malware. 

## Disclaimer
This tool is the result of several months of research and it is an attempt to bring a tool to the community dedicated to malware evasion techniques. It started as a side project and of course requires some improvements. Of course, it is not perfect nor magic!  

Please take notes of the following:
* This project currently works with python2.7 (it will be upgraded to python3 in a later version). 
* It might have some bugs or vulnerabilities. But the installation package installs this tool in a virtualenv to avoid any issue with the host.
* This tool is currently working only with a valid PE file (support of additional format file will be added in a later version). 
* There is currently no option supported, the standard output will provide you a full report.
* The analysis can take time depending of the PE size (more than 5 minutes for a PE bigger than 1MB).
* This tool has only been tested on Mac OS and Linux so far. 


## Getting Started
### Prerequisites
If you used the standard installation process, the only requirement is pip. https://pip.pypa.io/en/stable/installing/

### Package requirements

```bash
apt-get install pip 
apt-get install libfuzzy-dev
```

### Virtualenv
The tool is currently running under Virtualenv (https://virtualenv.pypa.io/en/latest/), which creates a virtual python work environment to avoid any issue with the current OS as well with the versioning. If not currently installed, the installation process will install it. 

You might want to install Virtualenv too:
```bash
MacOS: brew install virtualenv or pip install virtualenv
Linux: pip install virtualenv
```

###Variables To Modify 
Before to run the installation setup, you will need to modify the config.py files to put your own VirusTotal API. 

 Put your Virustotal API Key

```
APIKEY = "<enter_key"
```
Additionally, you might want to add your own Yara rules to scan a PE. This can be added in the file “module/yara-rules/user_rules.yar”.

### Quick install
To quickly try and run the tool you just need to run the following command:

```bash
chmod u+x unprotect/install.sh
./install.sh
# You are ready to go! 
```

The install.sh file will setup the virtualenv for unprotect, installs the dependencies required, and creates a symbolic link into the directory /usr/local/bin/unprotect. That way unprotect will be accessible anywhere on your system. 

### Custom install  
If you want to install by yourself the unprotect tool, you will need the following:
-	Virtualenv installed
-	Create your own env: 
```
virtualenv -p python2.7 unprotect_custom
```
-	Enable your virtual env: 
```
source unprotect/bin/activate
```
-	Install the dependencies: 
```
sudo pip install -r requirements.txt
```
-	Run unprotect: 
```
python unprotect.py
```
Note that you won’t be able to access unprotect anywhere on your system. You will also need to activate the virtualenv each time you want to run the tool. 

### Usage

The current version of Unprotect doesn’t support any options. The simple way to use unprotect is to run it against a PE file:
```
unprotect <PE_file>
```

### Licence
APACHE License version 2.0

