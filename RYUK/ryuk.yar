import "pe"

rule RANSOM_RYUK_DROPPER: RANSOMWARE RYUK 
{
        meta:
                Description="Detects specific Microsoft PE Signature used by RYUK DROPPERS"
                Author="Swisscom CSIRT"
                Date="2020-10-29"

        condition:
                uint16(0x00) == 0x5a4d and pe.version_info["ProductName"] contains "Microsoft Corp. SAPI5 samples"
                
}