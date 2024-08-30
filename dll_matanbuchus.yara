import "pe"

rule MAL_WIN_Matanbuchus_Loader
{
    meta:
        description = "Detects Matanbuchus malware"
        author = "Juanmadelg"
        date = "08/04/2024"
        referece = "https://github.com/pr0xylife/Matanbuchus/blob/main/Matanbuchus_07.03_2024.txt"
        hash = "1ca1315f03f4d1bca5867ad1c7a661033c49bbb16c4b84bea72caa9bc36bd98b"
    strings:
        $s1 = "** GET_CHECKSUM **"
        $s2 = "AppPolicyGetProcessTerminationMethod"
        $s3 = "win32.DLL" fullword //ascii
        $s4 = "DllRegisterServer"
        $s5 = "DllUnregisterServer"
        $s6 = "_RegisterDll@12"
        $s7 = "_UnregisterDll@4"
        $s8 = "** GET_MSG_BODY **" wide // From s7 to s12 are from UTF-16 results
        $s9 = "** CHOSEN_DATA_PUM" wide
        $s10 = "Start Monitoring A" wide
        $s11 = "Receiver - Got NAK" wide
        $s12 = "dMohOverrideActionF" wide
        $s13 = "ModemMonitor(RKMON" wide
        $s14 = "EmulateCallWaiting"
        $s15 = "operator co_await"
        $s16 = "operator<=>" fullword
        $s17 = "** StartIdle **"
    condition:
        pe.is_pe and
        filesize < 750KB and // Stat command. Size = 410624 (bytes) -> 410.624 kilobytes
        pe.imports("KERNEL32.dll","IsDebuggerPresent") and
        pe.exports("DllRegisterServer") and
        all of ($s*)
}