import "pe"

rule MAL_WIN_Latrodectus
{
    meta:
        description = "Rule to detect Latrodectus malware"
        author = "Juanmadelg"
        date = "08/18/2024"
        hash = "aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c"
    strings:
        $s1 = "D:\\Build\\PETRU-DEFAULT-SOURCES\\inc\\ptportmisc.h"
        $s2 = /[A-Z]:\\builds\\(\w|\d)*\\trufos_dll\\[A-Za-z]+.c/ // regex
        $s3 = "TrfLibSetOption for OPT_ADD_THREAD_TO_SEC_BYPASS"
        $s4 = "YbiP2iP" nocase
        $s5 = "\t cmdFileDelete:" wide
        $s6 = "\t cmdFileCopy:" wide
        $s7 = "trufos" wide
        $s8 = "2.5.4.62.761d05c Free Build" wide nocase
        $s9 = "2.5.4.62.761d05ct" wide nocase
    condition:
        uint16(0) == 0x5a4d and
        filesize < 750KB and
        pe.imports("Secur32.dll","GetUserNameExW") and // side-loading
        pe.dll_name == "trufos.dll" and
        all of ($s*)
}