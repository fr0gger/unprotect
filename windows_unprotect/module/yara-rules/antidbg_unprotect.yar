/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

import "pe"

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="NtGlobalFlags"
	condition:
		any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="QueryInformationProcess"
	condition:
		any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="CheckRemoteDebuggerPresent"
	condition:
		any of them
}

rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
	meta:
	    Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		weight = 1
	strings:
		$ ="SetInformationThread"
	condition:
		any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="DebugActiveProcess"
	condition:
		any of them
}




rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="GenerateConsoleCtrlEvent"
	condition:
		any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}

rule ThreadControl__Context : AntiDebug ThreadControl {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetThreadContext"
	condition:
		any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="__invoke__watson"
	condition:
		any of them
}

rule SEH__v3 : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"
	condition:
		any of them
}

rule SEH__v4 : AntiDebug SEH {
    // VS 8.0+
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "____except__handler4"
		$ = "____local__unwind4"
		$ = "__XcptFilter"
	condition:
		any of them
}

rule SEH__vba : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "vbaExceptHandler"
	condition:
		any of them
}

rule SEH__vectored : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"
	condition:
		any of them
}
rule Check_Debugger
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	condition:
		pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and
		pe.imports("kernel32.dll","IsDebuggerPresent")
}
rule Check_OutputDebugStringA_iat
{

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "Detect in IAT OutputDebugstringA"
		Date = "20/04/2015"

	condition:
		pe.imports("kernel32.dll","OutputDebugStringA")
}
rule Check_FindWindowA_iat {

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if FindWindowA() is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"

	strings:
		$ollydbg = "OLLYDBG"
		$windbg = "WinDbgFrameClass"

	condition:
		pe.imports("user32.dll","FindWindowA") and ($ollydbg or $windbg)
}

rule DebuggerCheck__MemoryWorkingSet : AntiDebug DebuggerCheck {
	meta:
		author = "Fernando Mercês"
		date = "2015-06"
		description = "Anti-debug process memory working set size check"
		reference = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"

	condition:
		pe.imports("kernel32.dll", "K32GetProcessMemoryInfo") and
		pe.imports("kernel32.dll", "GetCurrentProcess")
}

rule Debugging_API {
    meta:
        author = "x0r"
        description = "Checks if being debugged"
	version = "0.2"
    strings:
    	$d1 = "Kernel32.dll" nocase
        $c1 = "CheckRemoteDebuggerPresent"
        $c2 = "IsDebuggerPresent"
        $c3 = "OutputDebugString"
        $c4 = "ContinueDebugEvent"
        $c5 = "DebugActiveProcess"
    condition:
        $d1 and 1 of ($c*)
}
rule anti_dbgtools {
    meta:
        author = "x0r"
        description = "Checks for the presence of known debug tools"
	version = "0.1"
    strings:
        $f1 = "procexp.exe" nocase
        $f2 = "procmon.exe" nocase
        $f3 = "processmonitor.exe" nocase
        $f4 = "wireshark.exe" nocase
        $f5 = "fiddler.exe" nocase
        $f6 = "windbg.exe" nocase
        $f7 = "ollydbg.exe" nocase
        $f8 = "winhex.exe" nocase
        $f9 = "processhacker.exe" nocase
        $f10 = "hiew32.exe" nocase
        $c11 = "\\\\.\\NTICE"
        $c12 = "\\\\.\\SICE"
        $c13 = "\\\\.\\Syser"
        $c14 = "\\\\.\\SyserBoot"
        $c15 = "\\\\.\\SyserDbgMsg"
    condition:
        any of them
}
