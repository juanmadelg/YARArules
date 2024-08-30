rule MAL_Qbot_InfoStealer
{
    meta:
        description = "Detects Qbot/Quakbot malware"
        author = "Juanmadelg"
        date = "08/11/2024"
        reference = "https://bazaar.abuse.ch/sample/12094a47a9659b1c2f7c5b36e21d2b0145c9e7b2e79845a437508efa96e5f305/"
        hash = "12094a47a9659b1c2f7c5b36e21d2b0145c9e7b2e79845a437508efa96e5f305"
    strings:
        $s1 = "t$ A;u(t>@8(u%" 
        $s2 = "L!t$HL!t$@" 
        $s3 = /(http|https):\/\//
        $s4 = "C:\\Program Files\\Spyhunter"
        $s5 = "\\StringFileInfo\\%04x%04x\\ProductName"
        $s6 = "moov"
        $s7 = ".internetdownloadmanager.com"
        $s8 = "IsDebuggerPresent"
        $s9 = "RegDeleteKeyA"
        $s11 = "idmcchandler7_64.dll"
        $s12 = "GDI32.dll" nocase
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        all of ($s*)
}