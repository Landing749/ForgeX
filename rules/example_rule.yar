rule Suspicious_Base64_PowerShell
{
    meta:
        author = "Forgex"
        description = "Detects base64-encoded PowerShell invocation patterns"
        severity = "medium"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $b64_iex = "SQBFAFgA" // "IEX" in UTF-16LE base64
    condition:
        any of them
}
