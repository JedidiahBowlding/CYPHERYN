rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell encoded command invocation"
        severity = "medium"
    strings:
        $powershell = /powershell(\.exe)?/ nocase ascii wide
        $encoded = /-(enc|encodedcommand)[ \t]+[A-Za-z0-9+\/=]{20,}/ nocase ascii wide
    condition:
        $powershell and $encoded
}

rule Suspicious_Windows_Process_Injection_APIs
{
    meta:
        description = "Combination of Windows APIs commonly used for process injection"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" ascii wide
        $b = "WriteProcessMemory" ascii wide
        $c = "CreateRemoteThread" ascii wide
    condition:
        2 of them
}

rule Suspicious_Office_AutoOpen_Macro
{
    meta:
        description = "Office macro auto-execution markers"
        severity = "medium"
    strings:
        $a = "AutoOpen" nocase ascii wide
        $b = "Document_Open" nocase ascii wide
        $c = "Workbook_Open" nocase ascii wide
        $shell = "Shell(" nocase ascii wide
    condition:
        1 of ($a, $b, $c) and $shell
}
