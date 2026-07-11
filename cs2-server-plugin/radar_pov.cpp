#include "radar_pov.h"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
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

// Steal at least kAbsJmpSize bytes using a tiny fixed-length decoder for
// common prologue instructions only. Returns 0 on failure.
size_t MeasureStolenBytes(const uint8_t* p, size_t maxNeed = kAbsJmpSize)
{
    size_t total = 0;
    while (total < maxNeed && total < 28) {
        const uint8_t* i = p + total;
        size_t len = 0;

        // push r64 / pop
        if (i[0] >= 0x50 && i[0] <= 0x5F) {
            len = 1;
        }
        // REX push/pop r8-r15: 41 5x / 41 5x
        else if (i[0] == 0x41 && ((i[1] >= 0x50 && i[1] <= 0x5F))) {
            len = 2;
        }
        // REX.W push? rare. 40 53 push rbx etc.
        else if (i[0] == 0x40 && (i[1] >= 0x50 && i[1] <= 0x5F)) {
            len = 2;
        }
        // sub rsp, imm8: 48 83 EC xx
        else if (i[0] == 0x48 && i[1] == 0x83 && i[2] == 0xEC) {
            len = 4;
        }
        // sub rsp, imm32: 48 81 EC xx xx xx xx
        else if (i[0] == 0x48 && i[1] == 0x81 && i[2] == 0xEC) {
            len = 7;
        }
        // mov [rsp+imm8], r64: 48 89 xx 24 xx  (modrm with SIB often)
        else if (i[0] == 0x48 && i[1] == 0x89) {
            const uint8_t modrm = i[2];
            const uint8_t mod = modrm >> 6;
            const uint8_t rm = modrm & 7;
            if (mod == 1 && rm == 4) {
                len = 5; // SIB + disp8
            } else if (mod == 1) {
                len = 4;
            } else if (mod == 2 && rm == 4) {
                len = 8;
            } else if (mod == 2) {
                len = 7;
            } else if (mod == 3) {
                len = 3;
            } else if (mod == 0 && rm == 4) {
                len = 4; // SIB
            } else if (mod == 0) {
                len = 3;
            }
        }
        // mov rax, rsp: 48 8B C4
        else if (i[0] == 0x48 && i[1] == 0x8B && i[2] == 0xC4) {
            len = 3;
        }
        // mov reg, reg: 48 8B Cx (modrm mod=11)
        else if (i[0] == 0x48 && i[1] == 0x8B && (i[2] & 0xC0) == 0xC0) {
            len = 3;
        }
        // xor reg, reg: 33 C0 / 45 33 C0 etc.
        else if (i[0] == 0x33 && (i[1] & 0xC0) == 0xC0) {
            len = 2;
        } else if (i[0] == 0x45 && i[1] == 0x33 && (i[2] & 0xC0) == 0xC0) {
            len = 3;
        }
        // test reg, reg
        else if (i[0] == 0x48 && i[1] == 0x85 && (i[2] & 0xC0) == 0xC0) {
            len = 3;
        }
        // nop
        else if (i[0] == 0x90) {
            len = 1;
        }
        // int3
        else if (i[0] == 0xCC) {
            break;
        }

        if (len == 0) {
            // Unknown opcode — refuse rather than split an instruction.
            return 0;
        }
        total += len;
    }
    return total >= maxNeed ? total : 0;
}

bool InstallInlineHook(InlineHook& hook, void* target, void* detour)
{
    if (target == nullptr || detour == nullptr) {
        return false;
    }
    const size_t stolen = MeasureStolenBytes(static_cast<const uint8_t*>(target));
    if (stolen < kAbsJmpSize) {
        Log("Radar POV: cannot measure safe prologue at %p (stolen=%zu)", target, stolen);
        return false;
    }

    void* tramp = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (tramp == nullptr) {
        Log("Radar POV: VirtualAlloc trampoline failed");
        return false;
    }

    memcpy(hook.original, target, stolen);
    // trampoline: original bytes + abs jmp back to target+stolen
    memcpy(tramp, target, stolen);
    WriteAbsJmp(static_cast<uint8_t*>(tramp) + stolen, static_cast<uint8_t*>(target) + stolen);

    DWORD oldProt = 0;
    if (!VirtualProtect(target, stolen, PAGE_EXECUTE_READWRITE, &oldProt)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        Log("Radar POV: VirtualProtect failed (%lu)", GetLastError());
        return false;
    }
    WriteAbsJmp(target, detour);
    // NOP the rest of the stolen region so we don't leave partial ops.
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

// Find ConVar registration LEA of the cvar name, then find the sole code
// reader of the ConVar storage (FUN_180e1f000), its caller (main radar tick),
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

    // Registration function: contains LEA of the name. Nearby should also LEA
    // the help text; ConVar object is the first arg (usually via LEA rcx, [rip]).
    uintptr_t regFn = FindFunctionStart(client, nameXrefs[0]);
    if (regFn == 0) {
        Log("Radar POV: failed to find cvar registration function");
        return false;
    }
    Log("Radar POV: cvar registration fn @ %p", reinterpret_cast<void*>(regFn));

    // Inside registration, collect LEA targets in .data that look like ConVar
    // objects (first LEA rcx target that is inside the module data, not the string).
    uintptr_t convarObj = 0;
    {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(regFn);
        for (size_t i = 0; i + 7 < 0x200; ++i) {
            uintptr_t target = 0;
            size_t sz = 0;
            if (!DecodeLeaRip(p + i, regFn + i, target, sz)) {
                continue;
            }
            if (target == reinterpret_cast<uintptr_t>(cvarName)) {
                continue;
            }
            // Prefer first non-string LEA in the function body as ConVar thisptr.
            if (target >= reinterpret_cast<uintptr_t>(client.base) &&
                target < reinterpret_cast<uintptr_t>(client.base) + client.size) {
                // Skip if it points into a C-string (printable).
                const auto* s = reinterpret_cast<const char*>(target);
                if (s[0] != 'c' && s[0] != 'S' && s[0] != 'I') {
                    convarObj = target;
                    break;
                }
                // "cl_radar..." already skipped; help text starts with 'S'
                if (strncmp(s, "Set all players", 15) == 0) {
                    continue;
                }
                if (strncmp(s, "cl_", 3) != 0) {
                    convarObj = target;
                    break;
                }
            }
        }
    }
    if (convarObj == 0) {
        Log("Radar POV: ConVar object not resolved from registration");
        return false;
    }
    Log("Radar POV: ConVar object @ %p", reinterpret_cast<void*>(convarObj));

    // Readers of the ConVar object (DATA xrefs via LEA). Prefer the largest
    // non-registration function — that is the mode setup path, not atexit.
    const auto convarXrefs = FindLeaRipXrefs(client, convarObj);
    uintptr_t radarModeFn = 0;
    size_t bestModeSize = 0;
    auto approxSize = [](uintptr_t fn) -> size_t {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
        for (size_t i = 0x20; i < 0x800; ++i) {
            if (p[i] == 0xCC && p[i + 1] == 0xCC) {
                return i;
            }
        }
        return 0x100;
    };
    for (uintptr_t xref : convarXrefs) {
        uintptr_t fn = FindFunctionStart(client, xref);
        if (fn == 0 || fn == regFn) {
            continue;
        }
        const size_t sz = approxSize(fn);
        if (sz > bestModeSize) {
            bestModeSize = sz;
            radarModeFn = fn;
        }
    }
    if (radarModeFn == 0) {
        Log("Radar POV: radar mode function not found");
        return false;
    }
    Log("Radar POV: radar mode fn @ %p (approx size 0x%zx)", reinterpret_cast<void*>(radarModeFn), bestModeSize);

    // Find callers of radarModeFn via relative E8 scan of the whole module
    // (expensive but one-shot at install).
    uintptr_t radarTickFn = 0;
    {
        const uintptr_t mode = radarModeFn;
        for (size_t i = 0; i + 5 < client.size; ++i) {
            if (client.base[i] != 0xE8) {
                continue;
            }
            uintptr_t target = 0;
            if (!DecodeRel32Call(client.base + i, reinterpret_cast<uintptr_t>(client.base) + i, target)) {
                continue;
            }
            if (target != mode) {
                continue;
            }
            uintptr_t caller = FindFunctionStart(client, reinterpret_cast<uintptr_t>(client.base) + i);
            if (caller != 0 && caller != mode) {
                radarTickFn = caller;
                break;
            }
        }
    }
    if (radarTickFn == 0) {
        Log("Radar POV: radar tick function not found");
        return false;
    }
    Log("Radar POV: radar tick fn @ %p", reinterpret_cast<void*>(radarTickFn));

    // In tick: call sequence ... mode, next, players, ...
    // From Ghidra: after FUN_180e1f000 comes FUN_180e31f90 then FUN_180e328a0.
    const auto tickCalls = CollectDirectCalls(radarTickFn, 0x400);
    uintptr_t radarPlayersFn = 0;
    for (size_t i = 0; i < tickCalls.size(); ++i) {
        if (tickCalls[i] == radarModeFn && i + 2 < tickCalls.size()) {
            radarPlayersFn = tickCalls[i + 2];
            break;
        }
    }
    if (radarPlayersFn == 0) {
        // Fallback: pick a large-ish following call target.
        bool seenMode = false;
        int after = 0;
        for (uintptr_t c : tickCalls) {
            if (c == radarModeFn) {
                seenMode = true;
                continue;
            }
            if (seenMode) {
                ++after;
                if (after == 2) {
                    radarPlayersFn = c;
                    break;
                }
            }
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

    auto approxFnSize = [](uintptr_t fn) -> size_t {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
        for (size_t i = 0; i < 0x400; ++i) {
            if (p[i] == 0xCC && p[i + 1] == 0xCC) {
                return i;
            }
        }
        return 0x400;
    };

    std::vector<uintptr_t> earlyUnique;
    for (uintptr_t c : playerCalls) {
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

    // getSlot ≈ second direct call in the entry path (after getLocal).
    if (earlyUnique.size() >= 2) {
        getSlotFn = earlyUnique[1];
    }

    // getObserverTarget is a small helper (~0x30-0x80) among early calls.
    for (size_t i = 2; i < earlyUnique.size(); ++i) {
        const size_t sz = approxFnSize(earlyUnique[i]);
        if (sz >= 0x20 && sz <= 0x90) {
            getObsFn = earlyUnique[i];
            break;
        }
    }
    if (getObsFn == 0) {
        for (uintptr_t c : earlyUnique) {
            const size_t sz = approxFnSize(c);
            if (sz >= 0x20 && sz <= 0x90 && c != getSlotFn && c != earlyUnique[0]) {
                getObsFn = c;
                break;
            }
        }
    }

    // isEnemy: called just before the show-all flag test at +0x17760.
    // Scan the players function for disp32 0x00017760 and walk backward for E8.
    {
        const uint8_t* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
        const uint8_t flagDisp[4] = {0x60, 0x77, 0x01, 0x00}; // +0x17760 little-endian
        for (size_t i = 0; i + 4 < 0xC00; ++i) {
            if (memcmp(body + i, flagDisp, 4) != 0) {
                continue;
            }
            // Search backward up to 0x80 bytes for a relative call.
            const size_t backStart = i > 0x80 ? i - 0x80 : 0;
            for (size_t j = i; j-- > backStart;) {
                uintptr_t target = 0;
                if (!DecodeRel32Call(body + j, radarPlayersFn + j, target)) {
                    continue;
                }
                if (target == getSlotFn || target == getObsFn || target == earlyUnique[0]) {
                    continue;
                }
                const size_t sz = approxFnSize(target);
                // isEnemy is medium-sized (~0x80-0x180 in the dump).
                if (sz >= 0x40 && sz <= 0x280) {
                    isEnemyFn = target;
                    break;
                }
            }
            if (isEnemyFn != 0) {
                break;
            }
        }
    }

    // Fallback for isEnemy: medium-sized early-unique call that is not slot/obs/local.
    if (isEnemyFn == 0) {
        for (uintptr_t c : earlyUnique) {
            if (c == getSlotFn || c == getObsFn || c == earlyUnique[0]) {
                continue;
            }
            const size_t sz = approxFnSize(c);
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
