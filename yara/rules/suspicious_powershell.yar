rule Suspicious_PowerShell_Downloader : review {
    meta:
        author = "SentinelScan"
        description = "PowerShell download-and-execute strings; heuristic requiring analyst review"
        severity = "medium"
    strings:
        $ps = "powershell" nocase ascii wide
        $download = "DownloadString" nocase ascii wide
        $execute = "Invoke-Expression" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
