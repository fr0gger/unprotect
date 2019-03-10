/* Unprotect Project Yara Rule to detect evasion techniques - Thomas Roccia - @fr0gger */

import "pe"

rule AtomTable_Inject
{
    meta:
        Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        Description = " Detect AtomBombing technique"
    strings:
        $var1 = "GlobalAddAtom"
        $var2 = "GlobalGetAtomName"
        $var3 = "QueueUserAPC"
    condition:
        all of them
}

rule DLL_inject
{
    meta:
        Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        Description = "Check for DLL Injection"
    strings:
        $var1 = "OpenProcess"
        $var2 = "VirtualAllocEx"
        $var3 = "LoadLibraryA"
        $var4 = "CreateFileA"
        $var5 = "WriteProcessMemory"
        $var6 = "HeapAlloc"
        $var7 = "GetProcAddress"
        $var8 = "CreateRemoteThread"
    condition:
        all of them
}

rule Inject_Thread
{
    meta:
        author = "x0r modified by @fr0gger_"
        description = "Code injection with CreateRemoteThread in a remote process"
    strings:
        $c1 = "OpenProcess"
        $c2 = "VirtualAllocEx"
        $c3 = "NtWriteVirtualMemory"
        $c4 = "WriteProcessMemory"
        $c5 = "CreateRemoteThread"
        $c6 = "CreateThread"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 or $c6 or $c1 )
}

rule Win_Hook
{
    meta:
        author = "x0r"
        description = "Affect hook table"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"
    condition:
        $f1 and 1 of ($c*)
}
rule Process_Doppelganging
{
    meta:
        author = "McAfee ATR - Thomas Roccia - @fr0gger_"
        description = "Detect Process Doppelganging"
        reference = "https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf"
        mitre_id = "T1186"
    strings:
        $func1 = "CreateTransaction" nocase
        $func2 = "CreateFileTransacted" nocase
        $func3 = "WriteFile" nocase
        $func5 = "RollbackTransaction" nocase
        $func6 = "CreateProcess" nocase
        $func7 = "CreateProcessParameters"
    condition:
        uint16(0) == 0x5A4D and ($func1 or $func2 or $func5 or (all of them) or
        pe.imports("KtmW32.dll", "CreateTransaction") and
        pe.imports("Kernel32.dll", "CreateFileTransacted") and
        pe.imports("KtmW32.dll", "RollbackTransaction"))
}

rule PROPagate
{
    meta:
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect Window Properties Modfication"
        reference = "http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/"
        mitre_id = "T1055"
    strings:
        $func1 = "SetProp" nocase
        $func2 = "FindWindows" nocase
        $func3 = "GetProp" nocase
        $var1 = "UxSubclassInfo" nocase
        $var2 = "CC32SubclassInfo" nocase
    condition:
        uint16(0) == 0x5A4D and ($func1 and $func3 and ($var1 or $var2) or (all of them) or
        pe.imports("User32.dll", "SetProp") and
        pe.imports("User32.dll", "GetProp"))
}

rule Atom_Bombing
{
    meta:
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect AtomBombing Injection"
        reference = "https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows"
        mitre_id = "T1055"
    strings:
        $var1 = "GlobalAddAtom" nocase
        $var2 = "GlobalGetAtomName" nocase
        $var3 = "QueueUserAPC" nocase
        $var4 = "NtQueueApcThread" nocase
        $var5 = "NtSetContextThread" nocase
    condition:
        uint16(0) == 0x5A4D and (all of them or
        pe.imports("Kernel32.dll", "GlobalAddAtom") and
        pe.imports("Kernel32.dll", "GlobalGetAtomName") and
        pe.imports("Kernel32.dll", "QueueUserAPC"))
}

rule APC_Inject
{
   meta:
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect APC Injection"
        mitre_id = "T1055"
   strings:
        $func1 = "NtQueueApcThread" nocase
        $func2 = "NtResumeThread" nocase
        $func3 = "NTTestAlert" nocase
        $func4 = "QueueUserApc" nocase
   condition:
        uint16(0) == 0x5A4D and ($func1 and $func2 or all of them)
}

rule CTRL_Inject
{
   meta:
        author = "McAfee ATR - Thomas Roccia - @fr0gger_ "
        description = "Detect Control Inject"
        reference = "https://blog.ensilo.com/ctrl-inject"
        mitre_id = "T1055"
   strings:
        $func1 = "OpenProcess" nocase
        $func2 = "VirtualAllocEx" nocase
        $func3 = "WriteProcessMemory" nocase
        $func4 = "EncodePointer" nocase
        $func5 = "EncodeRemotePointer" nocase
        $func6 = "SetProcessValidCallTargets" nocase
   condition:
        uint16(0) == 0x5A4D and ($func1 and $func2 and ($func4 or $func5) and $func6 or (all of them))

}
