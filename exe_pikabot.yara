rule MAL_WIN_Pikabot
{
    meta:
        description = "Detects Pikabot malware"
        author = "Juanmadelg"
        date = "08/18/2024"
        hash = "7d18e238febf88bc7c868e3ee4189fd12a2aa4db21f66151bb4c15c0600eca6e"
    strings:
        $s1 = "C:\\vmagent_new\\bin\\joblist\\498883\\out\\Release\\QHFileSmasher.pdb" // PDB name itself can be enough 
        $s2 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\auxdata.cpp" wide nocase
        $s3 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin2.inl" wide nocase
        $s4 = "SOFTWARE\\360TotalSecurity\\Experience" wide nocase
        $s5 = "PromoUtil.exe" wide nocase
        $s6 = "F\\deepscan\\BAPI.dll" wide nocase
        $s7 = "360safe.exe" wide fullword
        $s8 = "QHFileSmasher.exe" wide
        $s9 = "File Smasher Application" wide nocase
        // $s10 = /((kernel?|user?|advapi?)32.dll)/ nocase // Commonn dlls
    condition:
        uint16(0) == 0x5a4d and
        filesize < 1500KB and
        all of them
}