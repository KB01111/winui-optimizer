/*
    AI Antivirus default YARA rules (bundled, offline-safe).

    Rules:
      - eicar_test_string: the industry-standard EICAR anti-malware test
        signature. The signature is written as a hex string on purpose so the
        rule file itself is not flagged by other antivirus products while YARA
        still matches the exact EICAR bytes inside scanned files.
      - powershell_download_cradle: PowerShell that downloads and executes
        remote content.
      - pe_writable_executable_section: a PE with at least one section marked
        both writable and executable (common in packed/obfuscated samples).

    Metadata keys understood by security-scanner:
      name        human readable rule name
      description human readable description
      severity    info | low | medium | high | critical
      score       deterministic score contribution (0-100)
*/

rule eicar_test_string
{
    meta:
        name = "EICAR anti-malware test file"
        description = "EICAR standard anti-malware test string (harmless, used to verify scanning)"
        severity = "high"
        score = 90
        author = "ai-antivirus"

    strings:
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 24 48 2B 48 2A }

    condition:
        $eicar
}

rule powershell_download_cradle
{
    meta:
        name = "PowerShell download cradle"
        description = "PowerShell expression that downloads and executes remote content"
        severity = "high"
        score = 45
        author = "ai-antivirus"

    strings:
        $iex = "IEX" ascii nocase
        $invoke_expression = "Invoke-Expression" ascii nocase
        $download_string = "DownloadString" ascii nocase
        $download_file = "DownloadFile" ascii nocase
        $webclient = "Net.WebClient" ascii nocase
        $invoke_webrequest = "Invoke-WebRequest" ascii nocase

    condition:
        (($iex or $invoke_expression) and ($download_string or $download_file) and $webclient)
        or
        (($iex or $invoke_expression) and $invoke_webrequest)
}

import "pe"

rule pe_writable_executable_section
{
    meta:
        name = "Writable and executable PE section"
        description = "Portable Executable contains a section marked both writable and executable"
        severity = "medium"
        score = 10
        author = "ai-antivirus"

    condition:
        pe.is_pe
        and for any section in pe.sections : (
            (section.characteristics & pe.SECTION_MEM_WRITE) != 0
            and (section.characteristics & pe.SECTION_MEM_EXECUTE) != 0
        )
}
