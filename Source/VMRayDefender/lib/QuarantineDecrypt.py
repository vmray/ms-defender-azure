"""
Decrypt Defender quarantine artifacts uploaded by SubmitEvidencesToVMRay.ps1.

The on-host PowerShell uploads encrypted blobs as-is from Defender's
SYSTEM-only quarantine directory. This module RC4-decrypts each ResourceData
blob using the hardcoded mpengine.dll key, then parses the documented format
to recover the original quarantined file bytes.

Format (from public reverse engineering — links below):
    DWORD at offset 0x08    sd_len  (security-descriptor length)
    header_len              0x28 + sd_len
    QWORD at offset (sd_len + 0x1C)  malfile_len  (original file size)
    bytes [header_len : header_len + malfile_len]   the original file

References:
    https://github.com/knez/defender-dump
    https://github.com/ernw/quarantine-formats/blob/master/docs/Windows_Defender.md
    https://blog.fox-it.com/2023/12/14/reverse-reveal-recover-windows-defender-quarantine-forensics/
"""

import struct


_RC4_KEY = bytes.fromhex(
    "1E87781B8DBAA844CE69702C0C78B786"
    "A3F623B738F5EDF9AF83530FB3FC54FA"
    "A21EB9CF1331FD0F0DA954F687CB9E18"
    "279697900E53FB317C9CBCE48E23D053"
    "71ECC15951B8F3649D7CA33ED68DC904"
    "7E82C9BAAD9799D0D458CB847CA9FFBE"
    "3C8A775233557DDE13A8B14087CC1BC8"
    "F10F6ECDD083A959CFF84A9D1D50755E"
    "3E191818AF23E2293558766D2C07E257"
    "12B2CA0B535ED8F6C56CE73D24BDD029"
    "1771861A54B4C285A9A3DB7ACA6D224A"
    "EACD621DB9F2A22ED1E9E11D75BED7DC"
    "0ECB0A8E68A2FF1263408DC808DFFD16"
    "4B116774CD0B9B8D05411ED6262E429B"
    "A495676B8398DB2F35D3C1B9CED52636"
    "F2765E1A95CB7CA4C3DDABDDBFF38253"
)


def _rc4(data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + _RC4_KEY[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = b ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def recover_original_file(encrypted_resource_data: bytes) -> bytes:
    """
    Decrypt an encrypted ResourceData blob and return the original quarantined
    file bytes. Raises ValueError if the format does not parse.
    """
    if len(encrypted_resource_data) < 0x28:
        raise ValueError("ResourceData blob too short to parse")

    plain = _rc4(encrypted_resource_data)
    sd_len = struct.unpack_from("<I", plain, 0x8)[0]
    header_len = 0x28 + sd_len
    if sd_len + 0x1C + 8 > len(plain):
        raise ValueError("ResourceData header truncated")
    malfile_len = struct.unpack_from("<Q", plain, sd_len + 0x1C)[0]
    end = header_len + malfile_len
    if end > len(plain):
        raise ValueError("ResourceData body truncated")
    return plain[header_len:end]
