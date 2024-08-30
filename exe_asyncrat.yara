rule MAL_WIN_AsyncRAT
{
    meta:
        description = "Detects AsyncRAT malware"
        author = "Juanmadelg"
        date = "08/30/2024"
        hash = "8579bd550e62d5c01e34f4fefc627374d7598d62aed57dda018ae2804b1219fb"
    strings:
        $s1 = "get_MachineName"
        $s2 = "get_OSFullName"
        $s3 = "CheckRemoteDebuggerPresent"
        $s4 = "isDebuggerPresent"
        $s5 = "DeleteSubKeyTree"
        $s6 = "ABRIL.exe"
        $s7 = "CreateSubKey"
        $s8 = "DeleteSubKey"
        $s9 = "RegistryKey"
        $s10 = "/c schtasks /create /f /sc onlogon /rl highest /tn " wide
        $s11 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $s12 = "timeout 3 > NUL" wide
        $s13 = "Select * from Win32_ComputerSystem" wide
        $s14 = "\\root\\SecurityCenter2" wide
        $s15 = "Select * from AntivirusProduct" wide
        $s16 = "AVRemoval.Class1" wide
        $s17 = "BackProxy.Class1" wide
        $s18 = "/c taskkill.exe /im chrome.exe /f" wide
        $s19 = "{0:D3}" wide
        $s20 = "{0:X2}" wide
        $s21 = "(never used) type $c1" wide
        $s22 = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
        $s23 = "Stub.exe" wide
    condition:
        uint16(0) == 0x5a4d and
        filesize < 75KB and
        all of ($s*)
}