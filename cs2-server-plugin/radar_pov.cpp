#include "radar_pov.h"

#include <atomic>
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
#include <MinHook.h>
#pragma comment(lib, "Psapi.lib")
#endif

namespace {

RadarPovLogFn g_log = nullptr;
std::atomic<bool> g_enabled{true};
std::atomic<bool> g_installed{false};
std::atomic<bool> g_aggressiveRedirects{false};

// Only redirect getLocal while CCSGO_HudRadar is building player icons.
thread_local int g_inRadarPlayerUpdate = 0;
// Observer-target *pawn* used as self for this radar tick (same type as getLocal).
thread_local void* g_povSelfPawn = nullptr;
thread_local bool g_povActive = false;

std::atomic<int> g_faultRadarMode{0};
std::atomic<int> g_faultRadarPlayers{0};
std::atomic<int> g_faultGetLocal{0};
std::atomic<int> g_faultResolve{0};
std::atomic<int> g_logPovOk{0};
std::atomic<int> g_logPovFail{0};

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
    return anywhereInFn & ~static_cast<uintptr_t>(0xF);
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

std::vector<uintptr_t> CollectDirectCalls(uintptr_t fn, size_t maxScan = 0x800)
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

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

using RadarModeFn = void(__fastcall*)(void* radar);
using RadarPlayersFn = void(__fastcall*)(void* radar);
using GetLocalFn = void*(__fastcall*)();
// getObs(localPawn) — first insn is mov rcx,[rcx+0x1220] (observer services on pawn).
using GetObserverTargetFn = void*(__fastcall*)(void* localPawn);

RadarModeFn g_origRadarMode = nullptr;
RadarPlayersFn g_origRadarPlayers = nullptr;
GetLocalFn g_origGetLocal = nullptr;
GetObserverTargetFn g_getObserverTarget = nullptr;

bool g_minhookInitialized = false;

// getLocal validates return with vtable+0x4D8 = IsPlayerPawn (index 155).
constexpr size_t kIsPlayerPawnVtableByteOff = 0x4D8;
// players / mode: call [vtable+0xAA0] before getObs.
constexpr size_t kIsObserverVtableByteOff = 0xAA0;
// Observer services pointer on pawn (getObs first load).
constexpr ptrdiff_t kPawnObserverServices = 0x1220;
constexpr ptrdiff_t kRadarShowAllFlagOffset = 0x17760;

const char* MhStatusName(MH_STATUS st)
{
    switch (st) {
    case MH_OK: return "MH_OK";
    case MH_ERROR_ALREADY_INITIALIZED: return "MH_ERROR_ALREADY_INITIALIZED";
    case MH_ERROR_NOT_INITIALIZED: return "MH_ERROR_NOT_INITIALIZED";
    case MH_ERROR_ALREADY_CREATED: return "MH_ERROR_ALREADY_CREATED";
    case MH_ERROR_NOT_CREATED: return "MH_ERROR_NOT_CREATED";
    case MH_ERROR_ENABLED: return "MH_ERROR_ENABLED";
    case MH_ERROR_DISABLED: return "MH_ERROR_DISABLED";
    case MH_ERROR_NOT_EXECUTABLE: return "MH_ERROR_NOT_EXECUTABLE";
    case MH_ERROR_UNSUPPORTED_FUNCTION: return "MH_ERROR_UNSUPPORTED_FUNCTION";
    case MH_ERROR_MEMORY_ALLOC: return "MH_ERROR_MEMORY_ALLOC";
    case MH_ERROR_MEMORY_PROTECT: return "MH_ERROR_MEMORY_PROTECT";
    case MH_ERROR_MODULE_NOT_FOUND: return "MH_ERROR_MODULE_NOT_FOUND";
    case MH_ERROR_FUNCTION_NOT_FOUND: return "MH_ERROR_FUNCTION_NOT_FOUND";
    default: return "MH_UNKNOWN";
    }
}

bool CreateAndEnableHook(void* target, void* detour, void** originalOut, const char* name)
{
    if (target == nullptr || detour == nullptr || originalOut == nullptr) {
        return false;
    }
    MH_STATUS st = MH_CreateHook(target, detour, originalOut);
    if (st != MH_OK) {
        Log("Radar POV: MH_CreateHook(%s) @ %p failed: %s (%d)", name, target, MhStatusName(st),
            static_cast<int>(st));
        return false;
    }
    st = MH_EnableHook(target);
    if (st != MH_OK) {
        Log("Radar POV: MH_EnableHook(%s) @ %p failed: %s (%d)", name, target, MhStatusName(st),
            static_cast<int>(st));
        MH_RemoveHook(target);
        *originalOut = nullptr;
        return false;
    }
    Log("Radar POV: MinHook enabled %s @ %p (trampoline %p)", name, target, *originalOut);
    return true;
}

void SetShowAllFlag(void* radar, bool showAll)
{
    if (radar == nullptr) {
        return;
    }
    auto* flags = reinterpret_cast<uint8_t*>(radar) + kRadarShowAllFlagOffset;
    if (showAll) {
        *flags = static_cast<uint8_t>(*flags | static_cast<uint8_t>(1));
    } else {
        *flags = static_cast<uint8_t>(*flags & ~static_cast<uint8_t>(1));
    }
}

// Call virtual bool method at byte offset (MSVC x64 thiscall = rcx).
bool CallVBool(void* obj, size_t vtableByteOff)
{
    if (obj == nullptr) {
        return false;
    }
    __try {
        void** vtable = *reinterpret_cast<void***>(obj);
        if (vtable == nullptr) {
            return false;
        }
        using Fn = uint8_t(__fastcall*)(void*);
        auto fn = reinterpret_cast<Fn>(vtable[vtableByteOff / sizeof(void*)]);
        if (fn == nullptr) {
            return false;
        }
        return fn(obj) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool IsPlayerPawn(void* ent)
{
    return CallVBool(ent, kIsPlayerPawnVtableByteOff);
}

bool LooksObserving(void* localPawn)
{
    if (localPawn == nullptr) {
        return false;
    }
    if (CallVBool(localPawn, kIsObserverVtableByteOff)) {
        return true;
    }
    // Fallback: non-null observer services (getObs loads [pawn+0x1220] without null check).
    __try {
        void* services =
            *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(localPawn) + kPawnObserverServices);
        return services != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Live radar "self" is a pawn. When spectating, self should be the target pawn.
void* ResolvePovSelfPawn(void* realLocalPawn)
{
    if (realLocalPawn == nullptr || g_getObserverTarget == nullptr) {
        return nullptr;
    }
    if (!LooksObserving(realLocalPawn)) {
        return nullptr;
    }
    void* target = nullptr;
    __try {
        target = g_getObserverTarget(realLocalPawn);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultResolve.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in getObs (code=0x%08lX) localPawn=%p", GetExceptionCode(),
                realLocalPawn);
        }
        return nullptr;
    }
    if (target == nullptr || target == realLocalPawn) {
        return nullptr;
    }
    // Must be a pawn — same type getLocal returns (never a controller).
    if (!IsPlayerPawn(target)) {
        if (g_logPovFail.fetch_add(1) == 0) {
            Log("Radar POV: getObs returned non-pawn %p (rejected)", target);
        }
        return nullptr;
    }
    return target;
}

// ---------------------------------------------------------------------------
// Detours
// ---------------------------------------------------------------------------

void __fastcall Hook_RadarMode(void* radar)
{
    __try {
        if (g_origRadarMode != nullptr) {
            g_origRadarMode(radar);
        }
        // Do not force show-all off here. players hook decides based on POV success.
        // Clearing here + failed POV left the radar empty.
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultRadarMode.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in Hook_RadarMode (code=0x%08lX) radar=%p",
                GetExceptionCode(), radar);
        }
    }
}

void* __fastcall Hook_GetLocal()
{
    void* real = nullptr;
    __try {
        if (g_origGetLocal != nullptr) {
            real = g_origGetLocal();
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultGetLocal.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in original getLocal (code=0x%08lX)", GetExceptionCode());
        }
        return nullptr;
    }

    if (!g_enabled.load(std::memory_order_relaxed) || g_inRadarPlayerUpdate <= 0 || !g_povActive) {
        return real;
    }
    if (g_povSelfPawn != nullptr) {
        return g_povSelfPawn;
    }
    return real;
}

void __fastcall Hook_RadarPlayers(void* radar)
{
    const bool wantPov = g_enabled.load(std::memory_order_relaxed);
    g_povSelfPawn = nullptr;
    g_povActive = false;

    if (wantPov) {
        ++g_inRadarPlayerUpdate;
    }

    __try {
        // Resolve POV *before* the engine update, using the real getLocal pawn.
        if (wantPov && g_origGetLocal != nullptr && g_getObserverTarget != nullptr) {
            void* realPawn = nullptr;
            __try {
                realPawn = g_origGetLocal();
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                realPawn = nullptr;
            }
            void* povPawn = ResolvePovSelfPawn(realPawn);
            if (povPawn != nullptr) {
                g_povSelfPawn = povPawn;
                g_povActive = true;
                SetShowAllFlag(radar, false);
                if (g_logPovOk.fetch_add(1) == 0) {
                    Log("Radar POV: active — self pawn %p -> observed pawn %p (show-all cleared)",
                        realPawn, povPawn);
                }
            } else {
                // Fail-safe: keep/force show-all so the radar is not empty.
                SetShowAllFlag(radar, true);
                if (g_logPovFail.fetch_add(1) == 0) {
                    Log("Radar POV: no observer target yet — show-all ON (fail-safe) local=%p",
                        realPawn);
                }
            }
        }

        if (g_origRadarPlayers != nullptr) {
            g_origRadarPlayers(radar);
        }

        // Re-apply flag after update (mode/other code may touch it mid-frame).
        if (wantPov && radar != nullptr) {
            if (g_povActive) {
                SetShowAllFlag(radar, false);
            } else {
                SetShowAllFlag(radar, true);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultRadarPlayers.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in Hook_RadarPlayers (code=0x%08lX) radar=%p povActive=%d "
                "pov=%p",
                GetExceptionCode(), radar, g_povActive ? 1 : 0, g_povSelfPawn);
        }
        // After a crash in the update, force show-all so next frames still show someone
        // if the exception path left partial state — best effort only.
        __try {
            if (radar != nullptr) {
                SetShowAllFlag(radar, true);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    if (wantPov && g_inRadarPlayerUpdate > 0) {
        --g_inRadarPlayerUpdate;
    }
    g_povSelfPawn = nullptr;
    g_povActive = false;
}

// ---------------------------------------------------------------------------
// Signature resolution
// ---------------------------------------------------------------------------

bool IsInsideModule(const ModuleInfo& mod, uintptr_t addr)
{
    const uintptr_t base = reinterpret_cast<uintptr_t>(mod.base);
    return addr >= base && addr < base + mod.size;
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

    uintptr_t convarObj = 0;
    uintptr_t regFn = 0;
    for (uintptr_t nameLea : nameXrefs) {
        regFn = FindFunctionStart(client, nameLea);
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

    const auto convarXrefs = FindLeaRipXrefs(client, convarObj);
    uintptr_t radarModeFn = 0;
    uintptr_t modeCallSite = 0;
    for (uintptr_t xref : convarXrefs) {
        uintptr_t fn = FindFunctionStart(client, xref);
        if (fn == 0 || fn == regFn) {
            continue;
        }
        const auto callSites = FindE8CallSites(client, fn);
        if (callSites.empty()) {
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

    uintptr_t radarPlayersFn = 0;
    {
        const uintptr_t scanFrom = modeCallSite + 5;
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
        // Prefer the largest of the first few calls as players (it is ~0xB00+; layout helpers smaller).
        // Fall back to after[1] which matches the known call order: mode, layout, players.
        if (afterMode.size() >= 2) {
            radarPlayersFn = afterMode[1];
            size_t bestSz = ApproxFnSize(radarPlayersFn);
            for (size_t i = 0; i < afterMode.size() && i < 4; ++i) {
                const size_t sz = ApproxFnSize(afterMode[i]);
                if (sz > bestSz && sz >= 0x400) {
                    bestSz = sz;
                    radarPlayersFn = afterMode[i];
                }
            }
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
    Log("Radar POV: radar players fn @ %p size=0x%zx", reinterpret_cast<void*>(radarPlayersFn),
        ApproxFnSize(radarPlayersFn));

    // players body: getLocal, getSlot, getObs(+0x1220), getTeam, ...
    const auto playerCalls = CollectDirectCalls(radarPlayersFn, 0xC00);
    if (playerCalls.size() < 3) {
        Log("Radar POV: unexpected call graph in players fn (%zu calls)", playerCalls.size());
        return false;
    }

    std::vector<uintptr_t> earlyUnique;
    for (uintptr_t c : playerCalls) {
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
        if (earlyUnique.size() >= 8) {
            break;
        }
    }

    uintptr_t getLocalFn = earlyUnique.empty() ? 0 : earlyUnique[0];
    uintptr_t getObsFn = 0;
    // getObs: contains imm32 0x1220 near the start.
    for (uintptr_t c : earlyUnique) {
        if (c == getLocalFn) {
            continue;
        }
        const uint8_t* b = reinterpret_cast<const uint8_t*>(c);
        for (size_t i = 0; i + 4 < 0x20; ++i) {
            if (b[i] == 0x20 && b[i + 1] == 0x12 && b[i + 2] == 0x00 && b[i + 3] == 0x00) {
                getObsFn = c;
                break;
            }
        }
        if (getObsFn != 0) {
            break;
        }
    }
    // Fallback index 2 from known Ghidra order.
    if (getObsFn == 0 && earlyUnique.size() >= 3) {
        getObsFn = earlyUnique[2];
    }

    // Sanity: getLocal should be small and contain call to IsPlayerPawn path.
    if (getLocalFn != 0) {
        Log("Radar POV: helpers getLocal=%p size=0x%zx getObs=%p size=0x%zx",
            reinterpret_cast<void*>(getLocalFn), ApproxFnSize(getLocalFn),
            reinterpret_cast<void*>(getObsFn), getObsFn ? ApproxFnSize(getObsFn) : 0);
    }

    if (getLocalFn == 0 || getObsFn == 0) {
        Log("Radar POV: helpers incomplete (getLocal=%p getObs=%p)",
            reinterpret_cast<void*>(getLocalFn), reinterpret_cast<void*>(getObsFn));
        // Still install mode+players for fail-safe show-all handling.
    }

    g_origRadarMode = reinterpret_cast<RadarModeFn>(radarModeFn);
    g_origRadarPlayers = reinterpret_cast<RadarPlayersFn>(radarPlayersFn);
    g_origGetLocal = getLocalFn != 0 ? reinterpret_cast<GetLocalFn>(getLocalFn) : nullptr;
    g_getObserverTarget = getObsFn != 0 ? reinterpret_cast<GetObserverTargetFn>(getObsFn) : nullptr;
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

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        Log("Radar POV: MH_Initialize failed: %s (%d)", MhStatusName(st), static_cast<int>(st));
        return false;
    }
    g_minhookInitialized = true;

    void* modeTarget = reinterpret_cast<void*>(g_origRadarMode);
    void* playersTarget = reinterpret_cast<void*>(g_origRadarPlayers);
    void* getLocalTarget = reinterpret_cast<void*>(g_origGetLocal);

    if (!CreateAndEnableHook(modeTarget, reinterpret_cast<void*>(&Hook_RadarMode),
                             reinterpret_cast<void**>(&g_origRadarMode), "radar_mode")) {
        MH_Uninitialize();
        g_minhookInitialized = false;
        return false;
    }

    if (!CreateAndEnableHook(playersTarget, reinterpret_cast<void*>(&Hook_RadarPlayers),
                             reinterpret_cast<void**>(&g_origRadarPlayers), "radar_players")) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        g_minhookInitialized = false;
        g_origRadarMode = nullptr;
        g_origRadarPlayers = nullptr;
        return false;
    }

    if (getLocalTarget != nullptr && g_getObserverTarget != nullptr) {
        if (!CreateAndEnableHook(getLocalTarget, reinterpret_cast<void*>(&Hook_GetLocal),
                                 reinterpret_cast<void**>(&g_origGetLocal), "getLocal")) {
            Log("Radar POV: getLocal hook failed — fail-safe show-all only");
            g_origGetLocal = reinterpret_cast<GetLocalFn>(getLocalTarget);
        }
    } else {
        Log("Radar POV: getLocal/getObs unresolved — fail-safe show-all only");
    }

    g_installed.store(true, std::memory_order_release);
    Log("Radar POV: installed (enabled=%d getLocal=%d getObs=%d) — self type is PAWN not controller",
        g_enabled.load() ? 1 : 0,
        g_origGetLocal != nullptr ? 1 : 0,
        g_getObserverTarget != nullptr ? 1 : 0);
    return true;
}

void UninstallHooks()
{
    if (g_minhookInitialized) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        g_minhookInitialized = false;
    }
    g_origRadarMode = nullptr;
    g_origRadarPlayers = nullptr;
    g_origGetLocal = nullptr;
    g_getObserverTarget = nullptr;
    g_installed.store(false, std::memory_order_release);
    Log("Radar POV: MinHook hooks removed");
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

void RadarPov_SetAggressiveRedirects(bool enabled)
{
    g_aggressiveRedirects.store(enabled, std::memory_order_relaxed);
    Log("Radar POV: aggressive_redirects=%d (legacy; unused)", enabled ? 1 : 0);
}

bool RadarPov_AggressiveRedirectsEnabled()
{
    return g_aggressiveRedirects.load(std::memory_order_relaxed);
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
    // Prefer FOG when POV works; Hook_RadarPlayers forces show-all if POV fails.
    queueCmd("cl_radar_show_all_players_when_spectating 0");
    queueCmd("cl_radar_square_when_spectating 0");
}
