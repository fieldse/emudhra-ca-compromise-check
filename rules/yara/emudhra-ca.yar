/*
  emudhra-ca.yar - YARA rules for files that still carry eMudhra G3 certificates (October 2026 compromise).
  Matches DER (keystores, compiled-in root stores) and PEM (CA bundles) on public-key bytes, so names and comments don't matter.
  Each key has three windows. PEM line breaks can split at most two, so one always matches.
  Source: https://github.com/fieldse/emudhra-ca-compromise-check  Revised 2026-10-31.
*/

rule eMudhra_G3_compromised_intermediate
{
  meta:
    description = "Contains one of the eight eMudhra G3 intermediates whose private keys are below 256"
    severity = "critical"
    reference = "https://github.com/fieldse/emudhra-ca-compromise-check"
    date = "2026-10-31"
  strings:
    $k_dv_tls_b_0 = { E7 9E D9 C0 4A 97 73 C4 73 5E 51 11 1D A8 5A C2 BD 5E }
    $k_dv_tls_b_0b = "\xe7\x9e\xd9\xc0\x4a\x97\x73\xc4\x73\x5e\x51\x11\x1d\xa8\x5a\xc2\xbd\x5e" base64
    $k_dv_tls_b_1 = { 2C BC 20 38 EC 1E 4F 0E 3B 81 2F C9 85 9E 1E 67 AF B0 }
    $k_dv_tls_b_1b = "\x2c\xbc\x20\x38\xec\x1e\x4f\x0e\x3b\x81\x2f\xc9\x85\x9e\x1e\x67\xaf\xb0" base64
    $k_dv_tls_b_2 = { D5 CC 03 D5 6B E6 78 B3 C3 8C B4 DC 93 7C A2 46 0E 23 }
    $k_dv_tls_b_2b = "\xd5\xcc\x03\xd5\x6b\xe6\x78\xb3\xc3\x8c\xb4\xdc\x93\x7c\xa2\x46\x0e\x23" base64
    $k_ov_tls_b_0 = { 73 89 7A A0 EB 3C FD CA 8B 12 40 2F FA F0 AB C4 E1 21 }
    $k_ov_tls_b_0b = "\x73\x89\x7a\xa0\xeb\x3c\xfd\xca\x8b\x12\x40\x2f\xfa\xf0\xab\xc4\xe1\x21" base64
    $k_ov_tls_b_1 = { C9 EE 2D 6D B8 3F AC 28 0C 5E 05 63 8A E7 A2 AC D7 1C }
    $k_ov_tls_b_1b = "\xc9\xee\x2d\x6d\xb8\x3f\xac\x28\x0c\x5e\x05\x63\x8a\xe7\xa2\xac\xd7\x1c" base64
    $k_ov_tls_b_2 = { 6C AA B2 CC 0A EE 4E 21 6C E9 79 DD 51 8A 4A F4 B6 26 }
    $k_ov_tls_b_2b = "\x6c\xaa\xb2\xcc\x0a\xee\x4e\x21\x6c\xe9\x79\xdd\x51\x8a\x4a\xf4\xb6\x26" base64
    $k_ev_tls_b_0 = { 25 DB A8 5A 64 D3 97 DA 0B 10 52 E9 EA 54 6E 48 7B EF }
    $k_ev_tls_b_0b = "\x25\xdb\xa8\x5a\x64\xd3\x97\xda\x0b\x10\x52\xe9\xea\x54\x6e\x48\x7b\xef" base64
    $k_ev_tls_b_1 = { C5 EA DC FE EF 75 A6 9B B5 D6 FC 01 F4 2B FB CA 6E B4 }
    $k_ev_tls_b_1b = "\xc5\xea\xdc\xfe\xef\x75\xa6\x9b\xb5\xd6\xfc\x01\xf4\x2b\xfb\xca\x6e\xb4" base64
    $k_ev_tls_b_2 = { 95 30 E7 9C F5 F0 86 64 68 F1 38 06 42 0A A5 C8 51 84 }
    $k_ev_tls_b_2b = "\x95\x30\xe7\x9c\xf5\xf0\x86\x64\x68\xf1\x38\x06\x42\x0a\xa5\xc8\x51\x84" base64
    $k_dv_tls_c_0 = { 3A 7A 78 62 C8 C4 4D 32 4D DD 69 03 3A 67 82 C0 EF EE }
    $k_dv_tls_c_0b = "\x3a\x7a\x78\x62\xc8\xc4\x4d\x32\x4d\xdd\x69\x03\x3a\x67\x82\xc0\xef\xee" base64
    $k_dv_tls_c_1 = { 3F A0 37 1B A3 BD 91 94 51 4E E1 72 A4 33 E3 63 0F 02 }
    $k_dv_tls_c_1b = "\x3f\xa0\x37\x1b\xa3\xbd\x91\x94\x51\x4e\xe1\x72\xa4\x33\xe3\x63\x0f\x02" base64
    $k_dv_tls_c_2 = { 2F EA 88 8B 74 BD FE 8F DA 4C 10 99 EE 6C A1 95 66 FE }
    $k_dv_tls_c_2b = "\x2f\xea\x88\x8b\x74\xbd\xfe\x8f\xda\x4c\x10\x99\xee\x6c\xa1\x95\x66\xfe" base64
    $k_ov_tls_c_0 = { 13 82 51 CD 52 AC 92 98 C1 C8 AA D9 77 32 1D EB 97 E7 }
    $k_ov_tls_c_0b = "\x13\x82\x51\xcd\x52\xac\x92\x98\xc1\xc8\xaa\xd9\x77\x32\x1d\xeb\x97\xe7" base64
    $k_ov_tls_c_1 = { A5 5D C8 AD 51 DC FC 9D 15 89 A1 59 7E 3A 51 20 E1 EF }
    $k_ov_tls_c_1b = "\xa5\x5d\xc8\xad\x51\xdc\xfc\x9d\x15\x89\xa1\x59\x7e\x3a\x51\x20\xe1\xef" base64
    $k_ov_tls_c_2 = { 81 81 AB 56 61 6D C4 5D 91 8A BC 09 F3 AB 0E 63 CF 79 }
    $k_ov_tls_c_2b = "\x81\x81\xab\x56\x61\x6d\xc4\x5d\x91\x8a\xbc\x09\xf3\xab\x0e\x63\xcf\x79" base64
    $k_ev_tls_c_0 = { 2D 56 E8 29 A6 FB 82 C6 4A 46 97 D9 60 AF 95 1E 90 67 }
    $k_ev_tls_c_0b = "\x2d\x56\xe8\x29\xa6\xfb\x82\xc6\x4a\x46\x97\xd9\x60\xaf\x95\x1e\x90\x67" base64
    $k_ev_tls_c_1 = { 06 DA 48 A8 AA EB 78 69 B6 A6 7E 6D 27 42 6E 04 42 AA }
    $k_ev_tls_c_1b = "\x06\xda\x48\xa8\xaa\xeb\x78\x69\xb6\xa6\x7e\x6d\x27\x42\x6e\x04\x42\xaa" base64
    $k_ev_tls_c_2 = { F2 A0 66 45 AE 7D 31 D5 86 6A D3 1A A3 D2 46 EB 0B 31 }
    $k_ev_tls_c_2b = "\xf2\xa0\x66\x45\xae\x7d\x31\xd5\x86\x6a\xd3\x1a\xa3\xd2\x46\xeb\x0b\x31" base64
    $k_ov_cs_b_0 = { AA BB 0F B0 66 6A CF CF 01 FA D5 2B FC FD 4C 2B F2 CB }
    $k_ov_cs_b_0b = "\xaa\xbb\x0f\xb0\x66\x6a\xcf\xcf\x01\xfa\xd5\x2b\xfc\xfd\x4c\x2b\xf2\xcb" base64
    $k_ov_cs_b_1 = { 0E 58 19 B6 1F E6 95 09 87 41 C8 C4 91 43 9B 34 A0 43 }
    $k_ov_cs_b_1b = "\x0e\x58\x19\xb6\x1f\xe6\x95\x09\x87\x41\xc8\xc4\x91\x43\x9b\x34\xa0\x43" base64
    $k_ov_cs_b_2 = { 2C 59 F3 63 9E 96 CD 6C 3D 4D B0 CE FE C2 6C 3D 62 51 }
    $k_ov_cs_b_2b = "\x2c\x59\xf3\x63\x9e\x96\xcd\x6c\x3d\x4d\xb0\xce\xfe\xc2\x6c\x3d\x62\x51" base64
    $k_ov_cs_c_0 = { B9 F0 E0 63 47 02 A6 9C A6 AA DD 44 3C FD 62 C4 1B 9B }
    $k_ov_cs_c_0b = "\xb9\xf0\xe0\x63\x47\x02\xa6\x9c\xa6\xaa\xdd\x44\x3c\xfd\x62\xc4\x1b\x9b" base64
    $k_ov_cs_c_1 = { 79 74 E7 69 1A 12 6F B9 6A FB 3E 34 C2 FD 3B C5 F4 83 }
    $k_ov_cs_c_1b = "\x79\x74\xe7\x69\x1a\x12\x6f\xb9\x6a\xfb\x3e\x34\xc2\xfd\x3b\xc5\xf4\x83" base64
    $k_ov_cs_c_2 = { F3 86 23 63 06 79 80 E2 50 3E 02 53 2D 65 46 23 5A 71 }
    $k_ov_cs_c_2b = "\xf3\x86\x23\x63\x06\x79\x80\xe2\x50\x3e\x02\x53\x2d\x65\x46\x23\x5a\x71" base64
  condition:
    any of them
}

rule eMudhra_G3_root
{
  meta:
    description = "Contains emSign ECC Root CA - G3 (removed from trust stores) or a G3 issuing root"
    severity = "high"
    reference = "https://github.com/fieldse/emudhra-ca-compromise-check"
    date = "2026-10-31"
  strings:
    $r_ecc_root_0 = { 23 A5 0C B8 2D 12 F5 28 F3 B1 B2 DD E2 02 12 80 9E 39 }
    $r_ecc_root_0b = "\x23\xa5\x0c\xb8\x2d\x12\xf5\x28\xf3\xb1\xb2\xdd\xe2\x02\x12\x80\x9e\x39" base64
    $r_ecc_root_1 = { 34 59 74 EC BB 06 1C E7 C0 72 AF E8 AE 2F E1 41 54 87 }
    $r_ecc_root_1b = "\x34\x59\x74\xec\xbb\x06\x1c\xe7\xc0\x72\xaf\xe8\xae\x2f\xe1\x41\x54\x87" base64
    $r_ecc_root_2 = { D0 86 23 BF 46 D5 8E 0F 3F 04 F4 D7 1C 92 7E F6 A5 63 }
    $r_ecc_root_2b = "\xd0\x86\x23\xbf\x46\xd5\x8e\x0f\x3f\x04\xf4\xd7\x1c\x92\x7e\xf6\xa5\x63" base64
    $r_root_tls_0 = { 5F 0F DC 3F AB 57 16 C4 BE 83 F5 B3 06 1F A0 90 E2 EF }
    $r_root_tls_0b = "\x5f\x0f\xdc\x3f\xab\x57\x16\xc4\xbe\x83\xf5\xb3\x06\x1f\xa0\x90\xe2\xef" base64
    $r_root_tls_1 = { 3E 3F 04 31 F4 19 78 84 2F B4 89 4F 10 3A 4F 26 58 EF }
    $r_root_tls_1b = "\x3e\x3f\x04\x31\xf4\x19\x78\x84\x2f\xb4\x89\x4f\x10\x3a\x4f\x26\x58\xef" base64
    $r_root_tls_2 = { E0 28 E2 A2 4A 75 87 95 D1 2C 19 EC B3 10 CE 2C 8B 7F }
    $r_root_tls_2b = "\xe0\x28\xe2\xa2\x4a\x75\x87\x95\xd1\x2c\x19\xec\xb3\x10\xce\x2c\x8b\x7f" base64
    $r_root_cs_0 = { 4A 5F 64 33 90 F4 54 0F CE 83 BE 9D CF 95 F3 C3 58 67 }
    $r_root_cs_0b = "\x4a\x5f\x64\x33\x90\xf4\x54\x0f\xce\x83\xbe\x9d\xcf\x95\xf3\xc3\x58\x67" base64
    $r_root_cs_1 = { F7 7F EA 06 49 2F 23 8F 29 5D 05 4A 39 DC 87 0A 00 19 }
    $r_root_cs_1b = "\xf7\x7f\xea\x06\x49\x2f\x23\x8f\x29\x5d\x05\x4a\x39\xdc\x87\x0a\x00\x19" base64
    $r_root_cs_2 = { 5F 44 53 98 BB 38 40 A5 1F D7 C4 66 E4 83 D5 FE D9 C1 }
    $r_root_cs_2b = "\x5f\x44\x53\x98\xbb\x38\x40\xa5\x1f\xd7\xc4\x66\xe4\x83\xd5\xfe\xd9\xc1" base64
  condition:
    any of them
}
