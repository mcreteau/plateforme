rule silex7_loaderx
{
    meta:
        description = "Detects the SILEX-7 LoaderX PE loader"
        author = "TomCaz"
        date = "2026-11-10"
        reference = "IT320-TR-2026-03 - data/rapport-acteur.txt"
        tlp = "clear"

    strings:
        $version = "LoaderX v2.3 build 0417" ascii
        $mutex = "Global\\SilexMutex_7A2F" ascii
        $run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHostUpdater" ascii
        $stage2 = "SilexStage2Payload" wide

    condition:
        uint16(0) == 0x5A4D and 3 of them
}


