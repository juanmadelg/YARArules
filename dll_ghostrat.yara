import "pe"

rule MAL_Gh0stRat_RAT_Aug04
{
    meta:
        description = " "
        author = "Juanmadelg"
        date = "08/06/2024"
        reference = "https://bazaar.abuse.ch/sample/ee49808f5f5b4c234ee5550442bf5565796b0c570f0332e3790eaafe1f91e9a2/"
        hash = "ee49808f5f5b4c234ee5550442bf5565796b0c570f0332e3790eaafe1f91e9a2"
    strings:
        $s1 = "CONNECT phase completed"
        $s2 = "CONNECT responded chunked"
        $s3 = "cf_socket_open() -> %d, fd=%d" //wide
        $s4 = "HAPPY-EYEBALLS"
        $s5 = "[%s] closing DATA connection"
        $s6 = "InitiateTransfer()"
        $s7 = "AllowServerConnect() -> %d"
        //$s8 = "username="%s",realm="%s",nonce="%s",cnonce="%s",nc="%s",digest-uri="%s",response=%s," wide
        $s9 = "CryptEncrypt"
        $s10 = "CryptDecrypt"
        $s11 = "IsDebuggerPresent"
    condition:
        uint16(0) == 0x5a4d and
        filesize < 740KB and
        pe.imports("bcrypt.dll") and
        //pe.exports(/^curl_[a-z]{1,7}_[a-z]{1,10}$/) and
        pe.exports(/^curl_(\w*)/) and
        all of ($s*)
}