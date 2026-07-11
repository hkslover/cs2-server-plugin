#include "mem_utils.h"

#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#endif

namespace MemUtils {
namespace {

struct PatternByte {
    uint8_t value = 0;
    uint8_t mask = 0;
};

bool ParseHexDigit(char c, uint8_t& out)
{
    if (c >= '0' && c <= '9') {
        out = static_cast<uint8_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        out = static_cast<uint8_t>(c - 'a' + 10);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        out = static_cast<uint8_t>(c - 'A' + 10);
        return true;
    }
    return false;
}

bool ParsePattern(const char* hex, std::vector<PatternByte>& out)
{
    out.clear();
    if (hex == nullptr) {
        return false;
    }
    size_t i = 0;
    while (hex[i] != '\0') {
        while (hex[i] == ' ' || hex[i] == '\t') {
            ++i;
        }
        if (hex[i] == '\0') {
            break;
        }
        const char c0 = hex[i++];
        char c1 = 0;
        if (hex[i] != '\0' && hex[i] != ' ' && hex[i] != '\t') {
            c1 = hex[i++];
        } else {
            if (c0 != '?') {
                out.clear();
                return false;
            }
            c1 = '?';
        }
        PatternByte pb = {};
        if (c0 == '?' && (c1 == '?' || c1 == 0)) {
            pb.value = 0;
            pb.mask = 0;
        } else {
            uint8_t hi = 0;
            uint8_t lo = 0;
            if (c0 == '?') {
                pb.mask = 0x0F;
                if (!ParseHexDigit(c1, lo)) {
                    out.clear();
                    return false;
                }
                pb.value = lo;
            } else if (c1 == '?') {
                pb.mask = 0xF0;
                if (!ParseHexDigit(c0, hi)) {
                    out.clear();
                    return false;
                }
                pb.value = static_cast<uint8_t>(hi << 4);
            } else {
                if (!ParseHexDigit(c0, hi) || !ParseHexDigit(c1, lo)) {
                    out.clear();
                    return false;
                }
                pb.value = static_cast<uint8_t>((hi << 4) | lo);
                pb.mask = 0xFF;
            }
        }
        out.push_back(pb);
    }
    return !out.empty();
}

bool MatchPatternAt(const uint8_t* p, const std::vector<PatternByte>& pat)
{
    if (p == nullptr || pat.empty()) {
        return false;
    }
    for (size_t i = 0; i < pat.size(); ++i) {
        if (pat[i].mask == 0) {
            continue;
        }
        if ((p[i] & pat[i].mask) != (pat[i].value & pat[i].mask)) {
            return false;
        }
    }
    return true;
}

}  // namespace

bool GetModuleInfo(const char* name, ModuleInfo& out)
{
#ifdef _WIN32
    HMODULE mod = GetModuleHandleA(name);
    if (mod == nullptr) {
        return false;
    }
    MODULEINFO info = {};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info))) {
        return false;
    }
    out.base = reinterpret_cast<uint8_t*>(info.lpBaseOfDll);
    out.size = static_cast<size_t>(info.SizeOfImage);
    return out.base != nullptr && out.size > 0;
#else
    (void)name;
    (void)out;
    return false;
#endif
}

uint32_t GetPeTimestamp(const ModuleInfo& mod)
{
#ifdef _WIN32
    if (mod.base == nullptr || mod.size < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > mod.size) {
        return 0;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(mod.base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    return nt->FileHeader.TimeDateStamp;
#else
    (void)mod;
    return 0;
#endif
}

bool IsInsideModule(const ModuleInfo& mod, uintptr_t addr)
{
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod.base);
    return mod.base != nullptr && addr >= base && addr < base + mod.size;
}

bool IsLikelyDataObject(const ModuleInfo& mod, uintptr_t addr)
{
    if (!IsInsideModule(mod, addr)) {
        return false;
    }
    const auto* s = reinterpret_cast<const char*>(addr);
    int printable = 0;
    for (int i = 0; i < 16; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0) {
            break;
        }
        if (c >= 32 && c < 127) {
            ++printable;
        } else {
            return true;
        }
    }
    return printable < 8;
}

const uint8_t* FindBytes(const uint8_t* begin, size_t size, const void* needle, size_t needleSize)
{
    if (begin == nullptr || needle == nullptr || needleSize == 0 || size < needleSize) {
        return nullptr;
    }
    const uint8_t* n = static_cast<const uint8_t*>(needle);
    const uint8_t* end = begin + size - needleSize;
    for (const uint8_t* p = begin; p <= end; ++p) {
        if (memcmp(p, n, needleSize) == 0) {
            return p;
        }
    }
    return nullptr;
}

const char* FindCString(const ModuleInfo& mod, const char* str)
{
    if (str == nullptr) {
        return nullptr;
    }
    const size_t len = strlen(str) + 1;
    return reinterpret_cast<const char*>(FindBytes(mod.base, mod.size, str, len));
}

bool MatchPattern(const uint8_t* p, size_t avail, const char* hex)
{
    std::vector<PatternByte> pat;
    if (!ParsePattern(hex, pat) || avail < pat.size()) {
        return false;
    }
    return MatchPatternAt(p, pat);
}

const uint8_t* FindPattern(const uint8_t* begin, size_t size, const char* hex)
{
    std::vector<PatternByte> pat;
    if (!ParsePattern(hex, pat) || begin == nullptr || size < pat.size()) {
        return nullptr;
    }
    const size_t plen = pat.size();
    const uint8_t* end = begin + size - plen;
    for (const uint8_t* p = begin; p <= end; ++p) {
        if (MatchPatternAt(p, pat)) {
            return p;
        }
    }
    return nullptr;
}

std::vector<const uint8_t*> FindPatternAll(const uint8_t* begin, size_t size, const char* hex,
                                           size_t maxHits)
{
    std::vector<const uint8_t*> hits;
    std::vector<PatternByte> pat;
    if (!ParsePattern(hex, pat) || begin == nullptr || size < pat.size()) {
        return hits;
    }
    const size_t plen = pat.size();
    const uint8_t* end = begin + size - plen;
    for (const uint8_t* p = begin; p <= end && hits.size() < maxHits; ++p) {
        if (MatchPatternAt(p, pat)) {
            hits.push_back(p);
        }
    }
    return hits;
}

bool DecodeLeaRip(const uint8_t* insn, uintptr_t insnAddr, uintptr_t& targetOut, size_t& sizeOut)
{
    if (insn == nullptr) {
        return false;
    }
    if ((insn[0] != 0x48 && insn[0] != 0x4C) || insn[1] != 0x8D) {
        return false;
    }
    const uint8_t modrm = insn[2];
    if ((modrm & 0xC7) != 0x05) {
        return false;
    }
    const int32_t rel = *reinterpret_cast<const int32_t*>(insn + 3);
    targetOut = insnAddr + 7 + static_cast<intptr_t>(rel);
    sizeOut = 7;
    return true;
}

bool DecodeRel32Call(const uint8_t* insn, uintptr_t insnAddr, uintptr_t& targetOut)
{
    if (insn == nullptr || insn[0] != 0xE8) {
        return false;
    }
    const int32_t rel = *reinterpret_cast<const int32_t*>(insn + 1);
    targetOut = insnAddr + 5 + static_cast<intptr_t>(rel);
    return true;
}

std::vector<uintptr_t> FindLeaRipXrefs(const ModuleInfo& mod, uintptr_t target)
{
    std::vector<uintptr_t> hits;
    if (mod.base == nullptr || mod.size < 7) {
        return hits;
    }
    for (size_t i = 0; i + 7 <= mod.size; ++i) {
        uintptr_t resolved = 0;
        size_t sz = 0;
        const uintptr_t addr = reinterpret_cast<uintptr_t>(mod.base + i);
        if (DecodeLeaRip(mod.base + i, addr, resolved, sz) && resolved == target) {
            hits.push_back(addr);
        }
    }
    return hits;
}

std::vector<uintptr_t> FindE8CallSites(const ModuleInfo& mod, uintptr_t fn)
{
    std::vector<uintptr_t> sites;
    if (mod.base == nullptr || fn == 0) {
        return sites;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod.base);
    for (size_t i = 0; i + 5 < mod.size; ++i) {
        if (mod.base[i] != 0xE8) {
            continue;
        }
        uintptr_t target = 0;
        if (!DecodeRel32Call(mod.base + i, base + i, target)) {
            continue;
        }
        if (target == fn) {
            sites.push_back(base + i);
        }
    }
    return sites;
}

std::vector<uintptr_t> CollectDirectCalls(uintptr_t fn, size_t maxScan)
{
    std::vector<uintptr_t> calls;
    if (fn == 0) {
        return calls;
    }
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    for (size_t i = 0; i + 5 < maxScan; ++i) {
        if (p[i] == 0xCC && p[i + 1] == 0xCC && i > 0x40) {
            break;
        }
        uintptr_t target = 0;
        if (DecodeRel32Call(p + i, fn + i, target)) {
            calls.push_back(target);
            i += 4;
        }
    }
    return calls;
}

bool LooksLikePrologue(const uint8_t* p)
{
    if (p == nullptr) {
        return false;
    }
    if (p[0] == 0x40 && (p[1] == 0x53 || p[1] == 0x55 || p[1] == 0x56 || p[1] == 0x57)) {
        return true;
    }
    if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) {
        return true;
    }
    if (p[0] == 0x48 && p[1] == 0x89 && (p[2] & 0xC7) == 0x44) {
        return true;
    }
    if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) {
        return true;
    }
    if (p[0] == 0x55 || p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57) {
        return true;
    }
    if (p[0] == 0x41 && (p[1] >= 0x54 && p[1] <= 0x57)) {
        return true;
    }
    if (p[0] == 0x84 && p[1] == 0xD2) {
        return true;
    }
    return false;
}

uintptr_t FindFunctionStart(const ModuleInfo& mod, uintptr_t anywhereInFn)
{
    if (mod.base == nullptr || anywhereInFn < reinterpret_cast<uintptr_t>(mod.base)) {
        return 0;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod.base);
    const uintptr_t minAddr = anywhereInFn > base + 0x2000 ? anywhereInFn - 0x2000 : base;
    for (uintptr_t p = anywhereInFn; p > minAddr; --p) {
        const uint8_t prev = *reinterpret_cast<const uint8_t*>(p - 1);
        if ((prev == 0xCC || prev == 0x90 || prev == 0xC3 || prev == 0xC2) &&
            LooksLikePrologue(reinterpret_cast<const uint8_t*>(p))) {
            return p;
        }
    }
    return anywhereInFn & ~static_cast<uintptr_t>(0xF);
}

size_t ApproxFnSize(uintptr_t fn)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    for (size_t i = 0x20; i < 0x2000; ++i) {
        if (p[i] == 0xCC && p[i + 1] == 0xCC) {
            return i;
        }
    }
    return 0x100;
}

}  // namespace MemUtils
