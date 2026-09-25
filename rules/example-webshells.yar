/*
  Example YARA rules for optional use with:
    python wpbdscanner.py -d /path/to/wp --yara rules/example-webshells.yar

  Requires: pip install yara-python

  These are simple illustrations — expand for your environment.
*/

rule PHP_Eval_Base64_Chain
{
    meta:
        description = "eval(base64_decode(...)) style backdoor"
        severity = "high"
    strings:
        $a = /eval\s*\(\s*base64_decode\s*\(/i
        $b = /eval\s*\(\s*gzinflate\s*\(\s*base64_decode/i
    condition:
        any of them
}

rule PHP_Eval_Superglobal
{
    meta:
        description = "Direct eval of user input"
        severity = "critical"
    strings:
        $a = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i
        $b = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i
    condition:
        any of them
}

rule Known_Webshell_Branding
{
    meta:
        description = "Known webshell family strings"
        severity = "critical"
    strings:
        $wso = "WSO " ascii
        $filesman = "FilesMan" ascii
        $b374k = "b374k" ascii
        $c99 = "c99shell" ascii nocase
        $alfa = "ALFA_DATA" ascii
    condition:
        any of them
}
