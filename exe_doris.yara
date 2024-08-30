import "pe"

rule MAL_Doris_Trojan
{
    meta:
        description = "Detects malware Doris"
        author = "Juanmadelg"
        date = "08/06/2024"
        reference = "https://bazaar.abuse.ch/sample/7ff1a20e8a37162f8a1a7bb00d7f5b9d0993cf7e232aa7e6373014fecd191d4d/"
        hash = "7ff1a20e8a37162f8a1a7bb00d7f5b9d0993cf7e232aa7e6373014fecd191d4d"
    strings:
        $s1 = "__GLOBAL_HEAP_SELECTED"
        $s2 = "__MSVCRT_HEAP_SELECT"
        $s3 = "TerminateProcess"
        $s4 = "SEIKO EPSON CORP." wide
        $s5 = "EPSON Scan" wide
        $s6 = "Estwm.exe" wide
        $s7 = "Estwm" wide nocase
        $s8 = "Hello World!" wide
    condition:
        uint16(0) == 0x5a4d and
        filesize < 55KB and
        pe.rich_signature.key == 3914518741 and
        all of ($s*)
}