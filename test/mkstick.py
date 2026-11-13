#!/usr/bin/env python3
"""Make a stormbootx-like boot stick image for the image-write test (#36).

    mkstick.py OUT ESP_MIB DEST=SRC [DEST=SRC ...]

OUT gets a protective MBR, a GPT at 512-byte LBAs (as a stormbootx
boot/<golden>-usb.img), one EFI system partition at 1 MiB holding a FAT16
with each SRC file copied to DEST (directories made as needed), and the
backup GPT at the end of OUT. Needs mkfs.fat and mtools.
"""
import os
import struct
import subprocess
import sys
import uuid
import zlib

out, esp_mib, files = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
esp = out + '.esp'
subprocess.run(['mkfs.fat', '-C', '-F', '16', '-n', 'STORMBOOT', esp, str(esp_mib * 1024)],
               check=True, stdout=subprocess.DEVNULL)
made = set()
for pair in files:
    dest, src = pair.split('=', 1)
    parts = dest.split('/')[:-1]
    for i in range(1, len(parts) + 1):
        d = '/'.join(parts[:i])
        if d not in made:
            subprocess.run(['mmd', '-i', esp, '::/' + d], check=True)
            made.add(d)
    subprocess.run(['mcopy', '-i', esp, src, '::/' + dest], check=True)

bs = 512
esp_len = os.path.getsize(esp)
first = (1 << 20) // bs
last = first + -(-esp_len // bs) - 1
total = last + 1 + 32 + 1                 # backup entries (16 KiB) + header
entries = bytearray(128 * 128)
entries[0:128] = (uuid.UUID('C12A7328-F81F-11D2-BA4B-00A0C93EC93B').bytes_le
                  + uuid.uuid4().bytes_le + struct.pack('<QQQ', first, last, 0)
                  + 'EFI system partition'.encode('utf-16-le').ljust(72, b'\0'))
ecrc = zlib.crc32(entries)
disk_guid = uuid.uuid4().bytes_le


def header(me, alt, table):
    h = struct.pack('<8sIIIIQQQQ16sQIII', b'EFI PART', 0x10000, 92, 0, 0,
                    me, alt, 34, total - 34, disk_guid, table, 128, 128, ecrc)
    return h[:16] + struct.pack('<I', zlib.crc32(h)) + h[20:]


with open(out, 'wb') as f:
    f.truncate(total * bs)
    mbr = bytearray(512)
    mbr[446:462] = struct.pack('<BBBBBBBBII', 0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF, 1,
                               min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b'\x55\xaa'
    f.seek(0)
    f.write(mbr)
    f.seek(bs)
    f.write(header(1, total - 1, 2))
    f.seek(2 * bs)
    f.write(entries)
    f.seek(first * bs)
    with open(esp, 'rb') as e:
        while chunk := e.read(1 << 22):
            f.write(chunk)
    f.seek((total - 33) * bs)
    f.write(entries)
    f.seek((total - 1) * bs)
    f.write(header(total - 1, 1, total - 33))
os.remove(esp)
