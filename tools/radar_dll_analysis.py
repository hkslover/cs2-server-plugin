#!/usr/bin/env python3
"""Map dll/client.dll and run ad-hoc radar-POV analysis queries.

Usage: python3 tools/radar_dll_analysis.py <rva> [len]
       python3 tools/radar_dll_analysis.py --calls <rva>
Maps the PE image (sections at VirtualAddresses) like the runtime loader and
disassembles / lists direct call targets from a given RVA.
"""
import struct
import sys

try:
    import capstone
except ImportError:
    print("pip install capstone", file=sys.stderr)
    sys.exit(2)

DLL = "dll/client.dll"


def load():
    with open(DLL, "rb") as fh:
        data = fh.read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    soi = struct.unpack_from("<I", data, pe + 24 + 56)[0]
    st = pe + 24 + optsz
    img = bytearray(soi)
    text = None
    for i in range(nsec):
        off = st + i * 40
        name = data[off : off + 8].rstrip(b"\0").decode()
        vs, va, rs, rp = struct.unpack_from("<IIII", data, off + 8)
        if va < soi and rs:
            cb = min(rs, soi - va, len(data) - rp)
            img[va : va + cb] = data[rp : rp + cb]
        if name == ".text":
            text = (va, max(vs, rs))
    if text is None:
        raise RuntimeError("no .text section")
    return img, text[0], text[1]


def fn_start(img, tva, tsz, addr):
    """Mirror MemUtils::FindFunctionStart: walk back to CC/90/C3/C2 + prologue."""
    lo = max(tva, addr - 0x2000)
    p = addr
    while p > lo:
        prev = img[p - 1]
        if prev in (0xCC, 0x90, 0xC3, 0xC2) and looks_prologue(img, p):
            return p
        p -= 1
    return addr & ~0xF


def looks_prologue(img, p):
    b = img[p : p + 3]
    if b[0] == 0x40 and b[1] in (0x53, 0x55, 0x56, 0x57):
        return True
    if b[0] == 0x48 and b[1] == 0x83 and b[2] == 0xEC:
        return True
    if b[0] == 0x48 and b[1] == 0x89 and (b[2] & 0xC7) == 0x44:
        return True
    if b[0] == 0x48 and b[1] == 0x8B and b[2] == 0xC4:
        return True
    if b[0] in (0x55, 0x53, 0x56, 0x57):
        return True
    if b[0] == 0x41 and 0x54 <= b[1] <= 0x57:
        return True
    return b[0] == 0x84 and b[1] == 0xD2


def fn_size(img, tsz, start):
    i = start + 0x20
    end = min(start + 0x2000, tva_limit)
    while i + 1 < end:
        if img[i] == 0xCC and img[i + 1] == 0xCC:
            return i - start
        i += 1
    return min(0x2000, tva_limit - start)


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
img, tva, tsz = load()
tva_limit = tva + tsz


def disasm(addr, length=0x120):
    code = bytes(img[addr : addr + length])
    for ins in md.disasm(code, addr):
        line = f"0x{ins.address:X}  {ins.bytes.hex(' '):<24} {ins.mnemonic} {ins.op_str}"
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            print(f"{line}   <== RVA 0x{int(ins.op_str, 16):X}>")
        else:
            print(line)


def calls(addr):
    size = fn_size(img, tsz, addr)
    code = bytes(img[addr : addr + size])
    seen = []
    for ins in md.disasm(code, addr):
        if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            if t not in seen:
                seen.append(t)
    return size, seen


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--calls":
        addr = int(sys.argv[2], 16)
        size, seen = calls(addr)
        print(f"fn 0x{addr:X} size~0x{size:X} unique direct call targets ({len(seen)}):")
        for t in seen:
            print(f"  0x{t:X}")
    else:
        addr = int(sys.argv[1], 16)
        n = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x120
        disasm(addr, n)
