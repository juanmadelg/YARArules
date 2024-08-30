import "pe"

rule MAL_WIN_IcedID
{
    meta:
        description = "Detects IcedID malware"
        author = "Juanmadelg"
        date = "08/19/2024"
        hash = "cdf05d78f3a588cfb721a36c6ae43365c45858a26a9145b719d8e98eee69e3fc"
    strings:
        $s1 = "/PASSWORD=password" wide
        $s2 = "Specifies the password to use." wide
    condition:
        pe.is_pe and
        filesize < 4500KB and
        pe.number_of_signatures == 2 and
        // Potential compromised certificate
        for any i in ( 0 .. pe.number_of_signatures ) : (
            pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
            pe.signatures[i].serial contains "02:fa:99:4d:66:0d:e6:59:ee:90:37:ec:b4:37:d7:66"
        ) and 
        all of them
}