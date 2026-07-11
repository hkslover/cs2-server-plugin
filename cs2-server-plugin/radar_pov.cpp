#include "radar_pov.h"

#include <atomic>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#endif

namespace {

RadarPovLogFn g_log = nullptr;
std::atomic<bool> g_enabled{true};
std::atomic<bool> g_installed{false};

// Set for the duration of CCSGO_HudRadar player-icon update so helper hooks
// only redirect when the radar is evaluating icons (not unrelated game code).
thread_local int g_inRadarPlayerUpdate = 0;

void Log(const char* fmt, ...)
{
    if (g_log == nullptr) {
        return;
    }
    char buf[1024] = {};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    g_log("%s", buf);
}

#ifdef _WIN32

// ---------------------------------------------------------------------------
// Module / pattern helpers
// ---------------------------------------------------------------------------

struct ModuleInfo {
    uint8_t* base = nullptr;
    size_t size = 0;
};

bool GetModuleInfo(const char* name, ModuleInfo& out)
{
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
    const size_t len = strlen(str) + 1;
    return reinterpret_cast<const char*>(FindBytes(mod.base, mod.size, str, len));
}

// LEA r64, [rip+rel32]  →  rex 8D modrm rel32  (7 bytes), modrm rm=101, mod=00
bool DecodeLeaRip(const uint8_t* insn, uintptr_t insnAddr, uintptr_t& targetOut, size_t& sizeOut)
{
    if (insn == nullptr) {
        return false;
    }
    // REX.W (48) or REX.WR (4C) + 8D
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

// Collect code addresses that load `target` via LEA [rip+disp].
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

bool LooksLikePrologue(const uint8_t* p)
{
    if (p == nullptr) {
        return false;
    }
    // Common MSVC x64 prologues
    // 40 53          push rbx
    // 48 83 EC xx    sub rsp, imm8
    // 48 89 5C 24    mov [rsp+..], rbx
    // 48 8B C4       mov rax, rsp
    // 55             push rbp
    // 41 5x          push r12-r15
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
    // Fall back to 16-byte alignment near the xref.
    return anywhereInFn & ~static_cast<uintptr_t>(0xF);
}

// Decode a relative E8 call at `insn` and return absolute target.
bool DecodeRel32Call(const uint8_t* insn, uintptr_t insnAddr, uintptr_t& targetOut)
{
    if (insn == nullptr || insn[0] != 0xE8) {
        return false;
    }
    const int32_t rel = *reinterpret_cast<const int32_t*>(insn + 1);
    targetOut = insnAddr + 5 + static_cast<intptr_t>(rel);
    return true;
}

// Walk a function body (until a few rets / max size) and collect absolute call targets.
std::vector<uintptr_t> CollectDirectCalls(uintptr_t fn, size_t maxScan = 0x800)
{
    std::vector<uintptr_t> calls;
    if (fn == 0) {
        return calls;
    }
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    for (size_t i = 0; i + 5 < maxScan; ++i) {
        // Stop at consecutive INT3 padding that usually follows a function.
        if (p[i] == 0xCC && p[i + 1] == 0xCC && i > 0x40) {
            break;
        }
        uintptr_t target = 0;
        if (DecodeRel32Call(p + i, fn + i, target)) {
            calls.push_back(target);
            i += 4; // loop adds 1
        }
    }
    return calls;
}

// ---------------------------------------------------------------------------
// Minimal x64 inline hook (14-byte absolute jmp)
// ---------------------------------------------------------------------------

constexpr size_t kAbsJmpSize = 14;

struct InlineHook {
    void* target = nullptr;
    void* detour = nullptr;
    void* trampoline = nullptr;
    uint8_t original[32] = {};
    size_t stolen = 0;
    bool active = false;
};

void WriteAbsJmp(void* at, void* to)
{
    auto* p = static_cast<uint8_t*>(at);
    // jmp qword ptr [rip+0]; dq target
    p[0] = 0xFF;
    p[1] = 0x25;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;
    *reinterpret_cast<void**>(p + 6) = to;
}

// Length of one common x64 prologue instruction. Returns 0 if unknown.
// Handles the MSVC prologues seen in CCSGO_HudRadar helpers (mov [rsp+x],
// push, sub rsp, mov reg, call rel32, call [reg+imm], lea, etc.).
size_t InsnLenPrologue(const uint8_t* i)
{
    if (i == nullptr) {
        return 0;
    }

    // push/pop r64
    if (i[0] >= 0x50 && i[0] <= 0x5F) {
        return 1;
    }
    // REX.B push/pop r8-r15: 41 5x
    if (i[0] == 0x41 && i[1] >= 0x50 && i[1] <= 0x5F) {
        return 2;
    }
    // REX push/pop: 40 5x (e.g. 40 53 push rbx)
    if (i[0] == 0x40 && i[1] >= 0x50 && i[1] <= 0x5F) {
        return 2;
    }
    // sub/add/cmp/and rsp, imm8: 48 83 /5 EC xx  (also /0-/7)
    if (i[0] == 0x48 && i[1] == 0x83) {
        return 4;
    }
    // sub rsp, imm32: 48 81 EC xx xx xx xx
    if (i[0] == 0x48 && i[1] == 0x81) {
        return 7;
    }
    // mov r/m64, r64  or  mov r64, r/m64  with REX.W: 48 89 / 48 8B
    // lea r64, m: 48 8D
    if (i[0] == 0x48 && (i[1] == 0x89 || i[1] == 0x8B || i[1] == 0x8D || i[1] == 0x85 ||
                         i[1] == 0x87 || i[1] == 0x3B || i[1] == 0x39)) {
        const uint8_t modrm = i[2];
        const uint8_t mod = modrm >> 6;
        const uint8_t rm = modrm & 7;
        size_t len = 3; // rex + opcode + modrm
        if (mod != 3 && rm == 4) {
            len += 1; // SIB
        }
        if (mod == 1) {
            len += 1; // disp8
        } else if (mod == 2) {
            len += 4; // disp32
        } else if (mod == 0 && rm == 5) {
            len += 4; // rip-relative disp32
        } else if (mod == 0 && rm == 4) {
            // SIB with mod=0: if base==5, disp32 follows SIB
            const uint8_t sib = i[3];
            if ((sib & 7) == 5) {
                len += 4;
            }
        }
        return len;
    }
    // non-REX mov r32, r/m32: 8B / 89
    if (i[0] == 0x8B || i[0] == 0x89) {
        const uint8_t modrm = i[1];
        const uint8_t mod = modrm >> 6;
        const uint8_t rm = modrm & 7;
        size_t len = 2;
        if (mod != 3 && rm == 4) {
            len += 1;
        }
        if (mod == 1) {
            len += 1;
        } else if (mod == 2 || (mod == 0 && rm == 5)) {
            len += 4;
        }
        return len;
    }
    // xor/test reg,reg short forms
    if ((i[0] == 0x33 || i[0] == 0x85 || i[0] == 0x3B) && (i[1] & 0xC0) == 0xC0) {
        return 2;
    }
    if (i[0] == 0x45 && (i[1] == 0x33 || i[1] == 0x85) && (i[2] & 0xC0) == 0xC0) {
        return 3;
    }
    // call rel32 / jmp rel32
    if (i[0] == 0xE8 || i[0] == 0xE9) {
        return 5;
    }
    // call/jmp r/m64: FF /2 or /4  — e.g. FF 90 78 09 00 00  call [rax+0x978]
    if (i[0] == 0xFF) {
        const uint8_t modrm = i[1];
        const uint8_t reg = (modrm >> 3) & 7;
        if (reg == 2 || reg == 4) {
            const uint8_t mod = modrm >> 6;
            const uint8_t rm = modrm & 7;
            size_t len = 2;
            if (mod != 3 && rm == 4) {
                len += 1;
            }
            if (mod == 1) {
                len += 1;
            } else if (mod == 2 || (mod == 0 && rm == 5)) {
                len += 4;
            }
            return len;
        }
    }
    // REX.W + FF call [reg+disp]
    if (i[0] == 0x48 && i[1] == 0xFF) {
        const uint8_t modrm = i[2];
        const uint8_t reg = (modrm >> 3) & 7;
        if (reg == 2 || reg == 4) {
            const uint8_t mod = modrm >> 6;
            const uint8_t rm = modrm & 7;
            size_t len = 3;
            if (mod != 3 && rm == 4) {
                len += 1;
            }
            if (mod == 1) {
                len += 1;
            } else if (mod == 2 || (mod == 0 && rm == 5)) {
                len += 4;
            }
            return len;
        }
    }
    // test al,imm8 / etc. rare in prologue
    if (i[0] == 0x90) {
        return 1; // nop
    }
    if (i[0] == 0xCC) {
        return 0;
    }
    return 0;
}

// Steal complete instructions totaling at least kAbsJmpSize bytes.
size_t MeasureStolenBytes(const uint8_t* p, size_t maxNeed = kAbsJmpSize)
{
    size_t total = 0;
    while (total < maxNeed && total < 28) {
        const size_t len = InsnLenPrologue(p + total);
        if (len == 0) {
            return 0;
        }
        total += len;
    }
    return total >= maxNeed ? total : 0;
}

// Copy stolen bytes into trampoline and fix E8/E9 relative displacements so
// they still target the original absolute destinations.
bool BuildTrampoline(uint8_t* tramp, const uint8_t* src, size_t stolen, uintptr_t srcAddr)
{
    size_t off = 0;
    while (off < stolen) {
        const size_t len = InsnLenPrologue(src + off);
        if (len == 0 || off + len > stolen) {
            return false;
        }
        memcpy(tramp + off, src + off, len);
        // Relocate relative call/jmp.
        if ((src[off] == 0xE8 || src[off] == 0xE9) && len == 5) {
            const int32_t oldRel = *reinterpret_cast<const int32_t*>(src + off + 1);
            const uintptr_t absTarget = srcAddr + off + 5 + static_cast<intptr_t>(oldRel);
            const uintptr_t newFrom = reinterpret_cast<uintptr_t>(tramp) + off + 5;
            const int64_t newRel64 = static_cast<int64_t>(absTarget - newFrom);
            if (newRel64 < INT32_MIN || newRel64 > INT32_MAX) {
                return false;
            }
            *reinterpret_cast<int32_t*>(tramp + off + 1) = static_cast<int32_t>(newRel64);
        }
        // RIP-relative lea/mov with modrm rm=5 mod=0 (after optional REX).
        // 48 8D/8B 05 xx xx xx xx
        if (len >= 7 && src[off] == 0x48 &&
            (src[off + 1] == 0x8D || src[off + 1] == 0x8B || src[off + 1] == 0x89) &&
            (src[off + 2] & 0xC7) == 0x05) {
            const int32_t oldRel = *reinterpret_cast<const int32_t*>(src + off + 3);
            const uintptr_t absTarget = srcAddr + off + 7 + static_cast<intptr_t>(oldRel);
            const uintptr_t newFrom = reinterpret_cast<uintptr_t>(tramp) + off + 7;
            const int64_t newRel64 = static_cast<int64_t>(absTarget - newFrom);
            if (newRel64 < INT32_MIN || newRel64 > INT32_MAX) {
                return false;
            }
            *reinterpret_cast<int32_t*>(tramp + off + 3) = static_cast<int32_t>(newRel64);
        }
        off += len;
    }
    return off == stolen;
}

bool InstallInlineHook(InlineHook& hook, void* target, void* detour)
{
    if (target == nullptr || detour == nullptr) {
        return false;
    }
    const auto* bytes = static_cast<const uint8_t*>(target);
    const size_t stolen = MeasureStolenBytes(bytes);
    if (stolen < kAbsJmpSize) {
        Log("Radar POV: cannot measure safe prologue at %p (stolen=%zu) bytes=%02x %02x %02x %02x %02x %02x %02x %02x",
            target, stolen, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]);
        return false;
    }

    void* tramp = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (tramp == nullptr) {
        Log("Radar POV: VirtualAlloc trampoline failed");
        return false;
    }

    memcpy(hook.original, target, stolen);
    if (!BuildTrampoline(static_cast<uint8_t*>(tramp), bytes, stolen,
                         reinterpret_cast<uintptr_t>(target))) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        Log("Radar POV: trampoline relocate failed at %p stolen=%zu", target, stolen);
        return false;
    }
    WriteAbsJmp(static_cast<uint8_t*>(tramp) + stolen, static_cast<uint8_t*>(target) + stolen);

    DWORD oldProt = 0;
    if (!VirtualProtect(target, stolen, PAGE_EXECUTE_READWRITE, &oldProt)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        Log("Radar POV: VirtualProtect failed (%lu)", GetLastError());
        return false;
    }
    WriteAbsJmp(target, detour);
    if (stolen > kAbsJmpSize) {
        memset(static_cast<uint8_t*>(target) + kAbsJmpSize, 0x90, stolen - kAbsJmpSize);
    }
    FlushInstructionCache(GetCurrentProcess(), target, stolen);
    VirtualProtect(target, stolen, oldProt, &oldProt);

    hook.target = target;
    hook.detour = detour;
    hook.trampoline = tramp;
    hook.stolen = stolen;
    hook.active = true;
    Log("Radar POV: hooked %p -> %p (stolen=%zu tramp=%p)", target, detour, stolen, tramp);
    return true;
}

void RemoveInlineHook(InlineHook& hook)
{
    if (!hook.active || hook.target == nullptr) {
        return;
    }
    DWORD oldProt = 0;
    if (VirtualProtect(hook.target, hook.stolen, PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy(hook.target, hook.original, hook.stolen);
        FlushInstructionCache(GetCurrentProcess(), hook.target, hook.stolen);
        VirtualProtect(hook.target, hook.stolen, oldProt, &oldProt);
    }
    if (hook.trampoline != nullptr) {
        VirtualFree(hook.trampoline, 0, MEM_RELEASE);
        hook.trampoline = nullptr;
    }
    hook.active = false;
}

// ---------------------------------------------------------------------------
// Resolved game functions (client.dll)
// ---------------------------------------------------------------------------

using RadarModeFn = void(__fastcall*)(void* radar);
using RadarPlayersFn = void(__fastcall*)(void* radar);
using IsEnemyFn = uint8_t(__fastcall*)(void* localPlayer, int otherSlot);
using GetObserverTargetFn = void*(__fastcall*)(void* localPlayer);
using GetPlayerSlotFn = int*(__fastcall*)(void* player, int* outSlot);

RadarModeFn g_origRadarMode = nullptr;
RadarPlayersFn g_origRadarPlayers = nullptr;
IsEnemyFn g_origIsEnemy = nullptr;
GetObserverTargetFn g_getObserverTarget = nullptr;
GetPlayerSlotFn g_origGetPlayerSlot = nullptr;

InlineHook g_hookRadarMode;
InlineHook g_hookRadarPlayers;
InlineHook g_hookIsEnemy;
InlineHook g_hookGetPlayerSlot;

// ConVar object for cl_radar_show_all_players_when_spectating (optional).
// Layout used only to force the cached value off after mode setup.
// advancedfx-style: value pointer often at +0x48-ish; we also clear radar flag.

constexpr ptrdiff_t kRadarShowAllFlagOffset = 0x17760;

void ForceClearShowAllFlag(void* radar)
{
    if (radar == nullptr) {
        return;
    }
    auto* flags = reinterpret_cast<uint8_t*>(radar) + kRadarShowAllFlagOffset;
    *flags = static_cast<uint8_t>(*flags & ~static_cast<uint8_t>(1));
}

// ---------------------------------------------------------------------------
// Detours
// ---------------------------------------------------------------------------

void __fastcall Hook_RadarMode(void* radar)
{
    if (g_origRadarMode != nullptr) {
        g_origRadarMode(radar);
    }
    if (g_enabled.load(std::memory_order_relaxed)) {
        // Ensure force-show-all is off so player filter uses team/spotted rules.
        ForceClearShowAllFlag(radar);
    }
}

void __fastcall Hook_RadarPlayers(void* radar)
{
    const bool pov = g_enabled.load(std::memory_order_relaxed);
    if (pov) {
        ++g_inRadarPlayerUpdate;
        ForceClearShowAllFlag(radar);
    }
    if (g_origRadarPlayers != nullptr) {
        g_origRadarPlayers(radar);
    }
    if (pov) {
        --g_inRadarPlayerUpdate;
    }
}

uint8_t __fastcall Hook_IsEnemy(void* localPlayer, int otherSlot)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarPlayerUpdate > 0 &&
        localPlayer != nullptr && g_getObserverTarget != nullptr && g_origIsEnemy != nullptr) {
        void* target = g_getObserverTarget(localPlayer);
        if (target != nullptr) {
            // Evaluate enemy/teammate relative to the observed player, not the
            // free spectator client.
            return g_origIsEnemy(target, otherSlot);
        }
    }
    if (g_origIsEnemy != nullptr) {
        return g_origIsEnemy(localPlayer, otherSlot);
    }
    return 1;
}

int* __fastcall Hook_GetPlayerSlot(void* player, int* outSlot)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarPlayerUpdate > 0 &&
        player != nullptr && g_getObserverTarget != nullptr && g_origGetPlayerSlot != nullptr) {
        void* target = g_getObserverTarget(player);
        if (target != nullptr) {
            // Spotted-by mask is indexed by the reference player's slot. Use
            // the observed player's slot so enemy red dots follow their FOV.
            return g_origGetPlayerSlot(target, outSlot);
        }
    }
    if (g_origGetPlayerSlot != nullptr) {
        return g_origGetPlayerSlot(player, outSlot);
    }
    return outSlot;
}

// ---------------------------------------------------------------------------
// Signature resolution from the Ghidra-mapped call chain
// ---------------------------------------------------------------------------

// Helpers for PE-ish address classification inside client.dll.
bool IsInsideModule(const ModuleInfo& mod, uintptr_t addr)
{
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod.base);
    return addr >= base && addr < base + mod.size;
}

// True if addr does not look like a C string (ConVar objects live in .data).
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
            return true; // binary payload
        }
    }
    // Long printable runs are strings in .rdata, not ConVar objects.
    return printable < 8;
}

size_t ApproxFnSize(uintptr_t fn)
{
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    for (size_t i = 0x20; i < 0x800; ++i) {
        if (p[i] == 0xCC && p[i + 1] == 0xCC) {
            return i;
        }
    }
    return 0x100;
}

// Return absolute addresses of E8 call sites that target `fn`.
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

// Find ConVar registration LEA of the cvar name, then the mode reader of that
// ConVar (must have E8 callers — excludes atexit), its caller (radar tick),
// then the player-update call (FUN_180e328a0).
bool ResolveRadarFunctions(const ModuleInfo& client)
{
    const char* cvarName = FindCString(client, "cl_radar_show_all_players_when_spectating");
    if (cvarName == nullptr) {
        Log("Radar POV: cvar name string not found in client.dll");
        return false;
    }
    Log("Radar POV: cvar string @ %p", cvarName);

    const auto nameXrefs = FindLeaRipXrefs(client, reinterpret_cast<uintptr_t>(cvarName));
    if (nameXrefs.empty()) {
        Log("Radar POV: no LEA xrefs to cvar name");
        return false;
    }
    Log("Radar POV: cvar name LEA xrefs=%zu (first @ %p)", nameXrefs.size(),
        reinterpret_cast<void*>(nameXrefs[0]));

    // Mega registration functions register many cvars. The ConVar object LEA
    // sits immediately next to the name-string LEA (typically within ±0x80),
    // not at the start of the whole registration blob.
    uintptr_t convarObj = 0;
    uintptr_t regFn = 0;
    for (uintptr_t nameLea : nameXrefs) {
        regFn = FindFunctionStart(client, nameLea);
        // Prefer LEA targets in a window just before/after the name LEA.
        // Correct ConVar is usually loaded once slightly before the name ptr.
        uintptr_t best = 0;
        intptr_t bestDist = 0x7fffffff;
        for (int delta = -0x80; delta <= 0x40; ++delta) {
            if (delta == 0) {
                continue;
            }
            const uintptr_t at = nameLea + static_cast<intptr_t>(delta);
            if (!IsInsideModule(client, at)) {
                continue;
            }
            uintptr_t target = 0;
            size_t sz = 0;
            if (!DecodeLeaRip(reinterpret_cast<const uint8_t*>(at), at, target, sz)) {
                continue;
            }
            if (target == reinterpret_cast<uintptr_t>(cvarName)) {
                continue;
            }
            if (!IsLikelyDataObject(client, target)) {
                continue;
            }
            // Prefer LEAs before the name (negative delta) and closest.
            const intptr_t dist = delta < 0 ? -delta : (delta + 0x1000);
            if (dist < bestDist) {
                bestDist = dist;
                best = target;
            }
        }
        if (best != 0) {
            convarObj = best;
            break;
        }
    }
    if (convarObj == 0) {
        Log("Radar POV: ConVar object not resolved near cvar name LEA");
        return false;
    }
    Log("Radar POV: ConVar object @ %p (reg fn @ %p)", reinterpret_cast<void*>(convarObj),
        reinterpret_cast<void*>(regFn));

    // Readers of the ConVar: registration, mode setup, atexit destructor.
    // Mode is the non-reg function that has E8 call sites (atexit has none).
    const auto convarXrefs = FindLeaRipXrefs(client, convarObj);
    uintptr_t radarModeFn = 0;
    uintptr_t modeCallSite = 0; // address of E8 that calls mode (inside tick)
    for (uintptr_t xref : convarXrefs) {
        uintptr_t fn = FindFunctionStart(client, xref);
        if (fn == 0 || fn == regFn) {
            continue;
        }
        const auto callSites = FindE8CallSites(client, fn);
        if (callSites.empty()) {
            // atexit / data-only references
            Log("Radar POV: skip ConVar reader @ %p (no E8 callers, size 0x%zx)",
                reinterpret_cast<void*>(fn), ApproxFnSize(fn));
            continue;
        }
        radarModeFn = fn;
        modeCallSite = callSites[0];
        Log("Radar POV: radar mode fn @ %p (E8 callers=%zu, size 0x%zx, call site @ %p)",
            reinterpret_cast<void*>(radarModeFn), callSites.size(), ApproxFnSize(fn),
            reinterpret_cast<void*>(modeCallSite));
        break;
    }
    if (radarModeFn == 0 || modeCallSite == 0) {
        Log("Radar POV: radar mode function not found");
        return false;
    }

    // Tick function start is best-effort (prolog scan can land early). Do NOT rely
    // on it to discover players — walk forward from the mode E8 site instead.
    // Ghidra sequence at the call site:
    //   call mode
    //   mov  rcx, rsi
    //   call intermediate   (layout/scale helper)
    //   mov  rcx, rsi
    //   call players        ← FUN_180e328a0
    uintptr_t radarPlayersFn = 0;
    {
        const uintptr_t scanFrom = modeCallSite + 5; // first byte after E8 to mode
        std::vector<uintptr_t> afterMode;
        const uint8_t* p = reinterpret_cast<const uint8_t*>(scanFrom);
        for (size_t i = 0; i + 5 < 0x80 && afterMode.size() < 6; ++i) {
            uintptr_t target = 0;
            if (!DecodeRel32Call(p + i, scanFrom + i, target)) {
                continue;
            }
            if (!IsInsideModule(client, target) || target == radarModeFn) {
                continue;
            }
            afterMode.push_back(target);
            i += 4;
        }
        if (afterMode.size() >= 2) {
            radarPlayersFn = afterMode[1];
        } else if (afterMode.size() == 1) {
            radarPlayersFn = afterMode[0];
        }
        Log("Radar POV: calls after mode: %zu (players candidate @ %p)", afterMode.size(),
            reinterpret_cast<void*>(radarPlayersFn));
        for (size_t i = 0; i < afterMode.size(); ++i) {
            Log("Radar POV:   after[%zu] = %p size=0x%zx", i,
                reinterpret_cast<void*>(afterMode[i]), ApproxFnSize(afterMode[i]));
        }
    }
    if (radarPlayersFn == 0) {
        Log("Radar POV: radar players function not found");
        return false;
    }
    Log("Radar POV: radar players fn @ %p", reinterpret_cast<void*>(radarPlayersFn));

    // Inside players fn (FUN_180e328a0 from Ghidra):
    //   call getLocal
    //   call getSlot(local, &slot)          ← hook (spotted mask index)
    //   ...
    //   call getObserverTarget(local)       ← call from hook
    //   ...
    //   call isEnemy(local, slot)           ← hook (team relative to target)
    //   test  [radar+0x17760], 1            ← show-all flag
    const auto playerCalls = CollectDirectCalls(radarPlayersFn, 0xC00);
    if (playerCalls.size() < 4) {
        Log("Radar POV: unexpected call graph in players fn (%zu calls)", playerCalls.size());
        return false;
    }

    std::vector<uintptr_t> earlyUnique;
    for (uintptr_t c : playerCalls) {
        // Discard bogus decode targets outside client.dll.
        if (!IsInsideModule(client, c)) {
            continue;
        }
        bool seen = false;
        for (uintptr_t u : earlyUnique) {
            if (u == c) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            earlyUnique.push_back(c);
        }
        if (earlyUnique.size() >= 16) {
            break;
        }
    }

    uintptr_t getSlotFn = 0;
    uintptr_t getObsFn = 0;
    uintptr_t isEnemyFn = 0;

    // From Ghidra entry path: getLocal, getSlot, getObserverTarget, ...
    if (earlyUnique.size() >= 2) {
        getSlotFn = earlyUnique[1];
    }
    if (earlyUnique.size() >= 3) {
        getObsFn = earlyUnique[2];
    }

    // isEnemy: called a few hundred bytes before the show-all flag test at +0x17760.
    {
        const uint8_t* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
        const uint8_t flagDisp[4] = {0x60, 0x77, 0x01, 0x00}; // +0x17760 little-endian
        for (size_t i = 0; i + 4 < 0xC00; ++i) {
            if (memcmp(body + i, flagDisp, 4) != 0) {
                continue;
            }
            // Prefer test/cmp forms: F6/F7/80/81 ... disp32
            // Walk farther back — isEnemy sits well before the flag test.
            const size_t backStart = i > 0x300 ? i - 0x300 : 0;
            for (size_t j = i; j-- > backStart;) {
                uintptr_t target = 0;
                if (!DecodeRel32Call(body + j, radarPlayersFn + j, target)) {
                    continue;
                }
                if (!IsInsideModule(client, target)) {
                    continue;
                }
                if (target == getSlotFn || target == getObsFn ||
                    (!earlyUnique.empty() && target == earlyUnique[0])) {
                    continue;
                }
                const size_t sz = ApproxFnSize(target);
                // isEnemy is medium-sized (~0x100). Exclude tiny helpers (cvar get,
                // math) and huge utilities.
                if (sz >= 0xA0 && sz <= 0x180) {
                    isEnemyFn = target;
                    break;
                }
            }
            if (isEnemyFn != 0) {
                break;
            }
        }
    }

    // Fallback: first medium-sized unique call after obs/slot that is not getLocal.
    if (isEnemyFn == 0) {
        for (uintptr_t c : earlyUnique) {
            if (c == getSlotFn || c == getObsFn || (!earlyUnique.empty() && c == earlyUnique[0])) {
                continue;
            }
            const size_t sz = ApproxFnSize(c);
            if (sz >= 0x60 && sz <= 0x200) {
                isEnemyFn = c;
                break;
            }
        }
    }

    if (getObsFn == 0 || getSlotFn == 0 || isEnemyFn == 0) {
        Log("Radar POV: helper resolution incomplete (obs=%p slot=%p enemy=%p)",
            reinterpret_cast<void*>(getObsFn),
            reinterpret_cast<void*>(getSlotFn),
            reinterpret_cast<void*>(isEnemyFn));
        // Still install mode + players hooks (clears show-all flag).
    } else {
        Log("Radar POV: helpers obs=%p slot=%p enemy=%p",
            reinterpret_cast<void*>(getObsFn),
            reinterpret_cast<void*>(getSlotFn),
            reinterpret_cast<void*>(isEnemyFn));
    }

    g_origRadarMode = reinterpret_cast<RadarModeFn>(radarModeFn);
    g_origRadarPlayers = reinterpret_cast<RadarPlayersFn>(radarPlayersFn);
    g_getObserverTarget = getObsFn != 0 ? reinterpret_cast<GetObserverTargetFn>(getObsFn) : nullptr;
    g_origGetPlayerSlot = getSlotFn != 0 ? reinterpret_cast<GetPlayerSlotFn>(getSlotFn) : nullptr;
    g_origIsEnemy = isEnemyFn != 0 ? reinterpret_cast<IsEnemyFn>(isEnemyFn) : nullptr;
    return true;
}

bool InstallHooks()
{
    ModuleInfo client = {};
    if (!GetModuleInfo("client.dll", client)) {
        Log("Radar POV: client.dll not loaded yet");
        return false;
    }
    Log("Radar POV: client.dll @ %p size=0x%zx", client.base, client.size);

    if (!ResolveRadarFunctions(client)) {
        return false;
    }

    if (!InstallInlineHook(g_hookRadarMode, reinterpret_cast<void*>(g_origRadarMode),
                           reinterpret_cast<void*>(&Hook_RadarMode))) {
        Log("Radar POV: failed to hook radar mode");
        return false;
    }
    g_origRadarMode = reinterpret_cast<RadarModeFn>(g_hookRadarMode.trampoline);

    if (!InstallInlineHook(g_hookRadarPlayers, reinterpret_cast<void*>(g_origRadarPlayers),
                           reinterpret_cast<void*>(&Hook_RadarPlayers))) {
        Log("Radar POV: failed to hook radar players");
        RemoveInlineHook(g_hookRadarMode);
        return false;
    }
    g_origRadarPlayers = reinterpret_cast<RadarPlayersFn>(g_hookRadarPlayers.trampoline);

    if (g_origIsEnemy != nullptr) {
        if (InstallInlineHook(g_hookIsEnemy, reinterpret_cast<void*>(g_origIsEnemy),
                              reinterpret_cast<void*>(&Hook_IsEnemy))) {
            g_origIsEnemy = reinterpret_cast<IsEnemyFn>(g_hookIsEnemy.trampoline);
        } else {
            Log("Radar POV: is-enemy hook failed (continuing with partial hooks)");
            g_origIsEnemy = nullptr;
        }
    }

    if (g_origGetPlayerSlot != nullptr) {
        if (InstallInlineHook(g_hookGetPlayerSlot, reinterpret_cast<void*>(g_origGetPlayerSlot),
                              reinterpret_cast<void*>(&Hook_GetPlayerSlot))) {
            g_origGetPlayerSlot = reinterpret_cast<GetPlayerSlotFn>(g_hookGetPlayerSlot.trampoline);
        } else {
            Log("Radar POV: get-slot hook failed (continuing with partial hooks)");
            g_origGetPlayerSlot = nullptr;
        }
    }

    g_installed.store(true, std::memory_order_release);
    Log("Radar POV: hooks installed (enabled=%d)", g_enabled.load() ? 1 : 0);
    return true;
}

void UninstallHooks()
{
    RemoveInlineHook(g_hookGetPlayerSlot);
    RemoveInlineHook(g_hookIsEnemy);
    RemoveInlineHook(g_hookRadarPlayers);
    RemoveInlineHook(g_hookRadarMode);
    g_origRadarMode = nullptr;
    g_origRadarPlayers = nullptr;
    g_origIsEnemy = nullptr;
    g_origGetPlayerSlot = nullptr;
    g_getObserverTarget = nullptr;
    g_installed.store(false, std::memory_order_release);
    Log("Radar POV: hooks removed");
}

#else // !_WIN32

bool InstallHooks()
{
    Log("Radar POV: not implemented on this platform");
    return false;
}

void UninstallHooks() {}

#endif // _WIN32

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void RadarPov_SetLogger(RadarPovLogFn logger)
{
    g_log = logger;
}

void RadarPov_SetEnabled(bool enabled)
{
    g_enabled.store(enabled, std::memory_order_relaxed);
    Log("Radar POV: enabled=%d", enabled ? 1 : 0);
}

bool RadarPov_IsEnabled()
{
    return g_enabled.load(std::memory_order_relaxed);
}

bool RadarPov_Install()
{
    if (g_installed.load(std::memory_order_acquire)) {
        return true;
    }
    return InstallHooks();
}

void RadarPov_Uninstall()
{
    if (!g_installed.load(std::memory_order_acquire)) {
        return;
    }
    UninstallHooks();
}

bool RadarPov_IsInstalled()
{
    return g_installed.load(std::memory_order_acquire);
}

void RadarPov_QueueEngineSetup(void (*queueCmd)(const char* cmd))
{
    if (queueCmd == nullptr || !g_enabled.load(std::memory_order_relaxed)) {
        return;
    }
    // Supporting cvars: turn off force-show-all; prefer non-square spectate radar.
    queueCmd("cl_radar_show_all_players_when_spectating 0");
    queueCmd("cl_radar_square_when_spectating 0");
}
