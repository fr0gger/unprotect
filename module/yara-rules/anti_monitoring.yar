rule disable_firewall {
    meta:
        author = "x0r"
        description = "Disable Firewall"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue"
        $r1 = "FirewallPolicy"
        $r2 = "EnableFirewall"
        $r3 = "FirewallDisableNotify"
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule disable_registry {
    meta:
        author = "x0r"
        description = "Disable Registry editor"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue"
        $r1 = "DisableRegistryTools"
        $r2 = "DisableRegedit"
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}

rule disable_dep {
    meta:
        author = "x0r"
        description = "Bypass DEP"
	version = "0.1"
    strings:
        $c1 = "EnableExecuteProtectionSupport"
        $c2 = "NtSetInformationProcess"
        $c3 = "VirtualProctectEx"
        $c4 = "SetProcessDEPPolicy"
        $c5 = "ZwProtectVirtualMemory"
    condition:
        any of them
}

rule disable_taskmanager {
    meta:
        author = "x0r"
        description = "Disable Task Manager"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr"
    condition:
        1 of ($p*) and 1 of ($r*)
}
rule check_patchlevel {
    meta:
        author = "x0r"
        description = "Check if hotfix are applied"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}
rule win_token {
    meta:
        author = "x0r"
        description = "Affect system token"
        version = "0.1"
    strings:
        $f1 = "advapi32.dll" nocase
        $c1 = "DuplicateTokenEx"
        $c2 = "AdjustTokenPrivileges"
        $c3 = "OpenProcessToken"
        $c4 = "LookupPrivilegeValueA"
    condition:
        $f1 and 1 of ($c*)
}
rule escalate_priv {
    meta:
        author = "x0r"
        description = "Escalade priviledges"
	version = "0.1"
    strings:
        $d1 = "Advapi32.dll" nocase
        $c1 = "SeDebugPrivilege"
        $c2 = "AdjustTokenPrivileges"
    condition:
        1 of ($d*) and 1 of ($c*)
}
