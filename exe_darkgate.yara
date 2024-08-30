rule MAL_WIN_Darkgate
{
    meta:
        description = "Detects DarkGate malware variant"
        author = "Juanmadelg"
        date = "08/17/2024"
        hash = "0efb25b41efef47892a1ed5dfbea4a8374189593217929ef6c46724d0580db23"
    strings:
        $s1 = "[AntiDebug] [user_check()] Username:" 
        $s2 = "DESKTOP-NAKFFMT"
        $s3 = "DESKTOP-VRSQLAG"
        $s4 = "LOUISE-PC"
        $s5 = "\\System32\\vmGuestLib.dll"
        // $s6 = /(kernel?|user?|shell?)32.dll/ nocase // Common dlls used by malware
        $s7 = "C:\\Users\\Alex\\Documents\\repos\\repos\\t34_new\\users\\MAGA\\cryptbase_meow\\x64\\Release\\cryptbase.pdb"
        $s8 = "rundll32 cleanhelper.dll T34 /k funtic321 1"
        // $s9 = /((kernel32|mscoree).dll)|((advapi|user)32)|kernelbase|ntdll/ wide nocase // Common dlls used by malware
        $s10 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h" wide
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1500KB and
        all of ($s*)
}