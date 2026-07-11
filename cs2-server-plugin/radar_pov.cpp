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
// Kept for console compatibility; true-POV no longer needs the old pawn redirects.
std::atomic<bool> g_aggressiveRedirects{false};

// Set for the duration of CCSGO_HudRadar player-icon update so getLocal only
// redirects when the radar is evaluating icons (not unrelated game code).
thread_local int g_inRadarPlayerUpdate = 0;

// Cached observed controller for the current radar tick (same thread as update).
thread_local void* g_povSelfController = nullptr;
thread_local void* g_realLocalController = nullptr;

// First-fault log throttles so a tight radar loop cannot flood csdm.log.
std::atomic<int> g_faultRadarMode{0};
std::atomic<int> g_faultRadarPlayers{0};
std::atomic<int> g_faultGetLocal{0};
std::atomic<int> g_faultResolve{0};

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
    // Pure helpers often start with: mov edx, [rcx+imm32]
    if (p[0] == 0x8B && (p[1] & 0xC7) == 0x81) {
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
// Hooks via MinHook
// ---------------------------------------------------------------------------

using RadarModeFn = void(__fastcall*)(void* radar);
using RadarPlayersFn = void(__fastcall*)(void* radar);
using GetLocalFn = void*(__fastcall*)();
using GetObserverTargetFn = void*(__fastcall*)(void* localController);
using GetControllerFromPawnFn = void*(__fastcall*)(void* pawn);

RadarModeFn g_origRadarMode = nullptr;
RadarPlayersFn g_origRadarPlayers = nullptr;
GetLocalFn g_origGetLocal = nullptr;
GetObserverTargetFn g_getObserverTarget = nullptr;
GetControllerFromPawnFn g_getControllerFromPawn = nullptr;

// Fallback when pure GetControllerFromPawn helper is not found.
void** g_entityListChunks = nullptr; // chunk table base (engine: table[idx>>9])
uintptr_t g_entityListGlobalSlot = 0; // &global holding chunk table*; re-read if null at install
ptrdiff_t g_offMhController = 0x13d0; // schema default for this dump; refined at runtime
// Controller field used by getObs: mov rcx, [rcx+0x1220]
constexpr ptrdiff_t kControllerObserverServices = 0x1220;
// IsObserver-ish check in players: call [vtable+0xaa0]
constexpr size_t kIsObserverVtableByteOff = 0xaa0;

bool g_minhookInitialized = false;

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

// Radar show-all bit written by mode setup when spectating + cvar.
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
// Entity handle resolve (matches engine: index&0x7fff, chunk>>9, stride 0x70)
// ---------------------------------------------------------------------------

void RefreshEntityListChunks()
{
    if (g_entityListChunks != nullptr) {
        return;
    }
    if (g_entityListGlobalSlot == 0) {
        return;
    }
    void* list = *reinterpret_cast<void**>(g_entityListGlobalSlot);
    if (list != nullptr) {
        g_entityListChunks = reinterpret_cast<void**>(list);
    }
}

void* ResolveEntityHandle(uint32_t handle)
{
    if (handle == 0xFFFFFFFFu || handle == 0xFFFFFFFEu) {
        return nullptr;
    }
    RefreshEntityListChunks();
    void** chunks = g_entityListChunks;
    if (chunks == nullptr) {
        return nullptr;
    }
    const uint32_t index = handle & 0x7FFFu;
    const uint32_t chunkIndex = index >> 9;
    const uint32_t entryIndex = index & 0x1FFu;
    if (chunkIndex > 0x3F) {
        return nullptr;
    }
    uint8_t* chunk = reinterpret_cast<uint8_t*>(chunks[chunkIndex]);
    if (chunk == nullptr) {
        return nullptr;
    }
    uint8_t* identity = chunk + static_cast<size_t>(entryIndex) * 0x70u;
    // identity+0x10 holds the full handle for serial match
    const uint32_t stored = *reinterpret_cast<uint32_t*>(identity + 0x10);
    if (stored != handle) {
        return nullptr;
    }
    return *reinterpret_cast<void**>(identity); // CEntityInstance*
}

void* GetControllerFromPawnFallback(void* pawn)
{
    if (pawn == nullptr || g_offMhController <= 0) {
        return nullptr;
    }
    const uint32_t handle =
        *reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(pawn) + g_offMhController);
    return ResolveEntityHandle(handle);
}

void* GetControllerFromPawn(void* pawn)
{
    if (pawn == nullptr) {
        return nullptr;
    }
    if (g_getControllerFromPawn != nullptr) {
        __try {
            void* ctrl = g_getControllerFromPawn(pawn);
            if (ctrl != nullptr) {
                return ctrl;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (g_faultResolve.fetch_add(1) == 0) {
                Log("Radar POV: EXCEPTION in GetControllerFromPawn helper (code=0x%08lX)",
                    GetExceptionCode());
            }
        }
    }
    __try {
        return GetControllerFromPawnFallback(pawn);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultResolve.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in handle resolve (code=0x%08lX)", GetExceptionCode());
        }
        return nullptr;
    }
}

bool ControllerLooksObserving(void* controller)
{
    if (controller == nullptr) {
        return false;
    }
    __try {
        // Prefer the same vtable method players uses (byte offset 0xaa0).
        void** vtable = *reinterpret_cast<void***>(controller);
        if (vtable != nullptr) {
            using IsObsFn = uint8_t(__fastcall*)(void*);
            auto fn = reinterpret_cast<IsObsFn>(vtable[kIsObserverVtableByteOff / sizeof(void*)]);
            if (fn != nullptr && fn(controller) != 0) {
                return true;
            }
        }
        // Fallback: observer services pointer at +0x1220 (getObs first load).
        void* services =
            *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(controller) + kControllerObserverServices);
        return services != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Resolve "self" for radar: observed player's controller when spectating.
void* ResolvePovSelfController(void* realLocal)
{
    if (realLocal == nullptr || g_getObserverTarget == nullptr) {
        return nullptr;
    }
    if (!ControllerLooksObserving(realLocal)) {
        return nullptr;
    }
    void* pawn = nullptr;
    __try {
        pawn = g_getObserverTarget(realLocal);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultResolve.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in getObs (code=0x%08lX) local=%p", GetExceptionCode(),
                realLocal);
        }
        return nullptr;
    }
    if (pawn == nullptr || pawn == realLocal) {
        return nullptr;
    }
    void* ctrl = GetControllerFromPawn(pawn);
    // If pawn already *is* a controller path failure, or handle points to self, skip.
    if (ctrl == nullptr || ctrl == realLocal) {
        return nullptr;
    }
    return ctrl;
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
        if (g_enabled.load(std::memory_order_relaxed) && radar != nullptr) {
            ForceClearShowAllFlag(radar);
        }
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

    if (!g_enabled.load(std::memory_order_relaxed) || g_inRadarPlayerUpdate <= 0) {
        return real;
    }

    // Reuse cached POV self for this radar tick (getLocal may be called once,
    // but keep the path safe if the engine calls it again inside the update).
    if (g_povSelfController != nullptr) {
        return g_povSelfController;
    }
    if (g_realLocalController == nullptr) {
        g_realLocalController = real;
    }

    void* pov = ResolvePovSelfController(real);
    if (pov != nullptr) {
        g_povSelfController = pov;
        return pov;
    }
    return real;
}

void __fastcall Hook_RadarPlayers(void* radar)
{
    const bool pov = g_enabled.load(std::memory_order_relaxed);
    if (pov) {
        ++g_inRadarPlayerUpdate;
        g_povSelfController = nullptr;
        g_realLocalController = nullptr;
    }
    __try {
        if (pov && radar != nullptr) {
            ForceClearShowAllFlag(radar);
        }
        if (g_origRadarPlayers != nullptr) {
            g_origRadarPlayers(radar);
        }
        if (pov && radar != nullptr) {
            // Mode can re-set the bit; clear again after player icons.
            ForceClearShowAllFlag(radar);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultRadarPlayers.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in Hook_RadarPlayers (code=0x%08lX) radar=%p",
                GetExceptionCode(), radar);
        }
    }
    if (pov && g_inRadarPlayerUpdate > 0) {
        --g_inRadarPlayerUpdate;
        g_povSelfController = nullptr;
        g_realLocalController = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Signature resolution from the Ghidra-mapped call chain
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
    for (size_t i = 0x20; i < 0x800; ++i) {
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

// Discover C_BasePlayerPawn::m_hController offset from schema field registration
// near the "m_hController" string (mov dword [reg+0x10], imm32).
bool ResolveMhControllerOffset(const ModuleInfo& client)
{
    const char* name = FindCString(client, "m_hController");
    if (name == nullptr) {
        Log("Radar POV: m_hController string missing; using default 0x%zx",
            static_cast<size_t>(g_offMhController));
        return g_offMhController > 0;
    }
    const auto xrefs = FindLeaRipXrefs(client, reinterpret_cast<uintptr_t>(name));
    for (uintptr_t lea : xrefs) {
        // Search a window after the LEA for: C7 40 10 xx xx xx xx  (mov [rax+0x10], imm)
        // or C7 44 24 xx xx xx xx xx (mov [rsp+..], imm) used by some registrars.
        const uint8_t* p = reinterpret_cast<const uint8_t*>(lea);
        for (int i = 0; i < 0x40; ++i) {
            if (p[i] == 0xC7 && p[i + 1] == 0x40 && p[i + 2] == 0x10) {
                const uint32_t off = *reinterpret_cast<const uint32_t*>(p + i + 3);
                if (off >= 0x100 && off < 0x4000) {
                    g_offMhController = static_cast<ptrdiff_t>(off);
                    Log("Radar POV: m_hController offset=0x%zx (schema)",
                        static_cast<size_t>(g_offMhController));
                    return true;
                }
            }
            if (p[i] == 0xC7 && p[i + 1] == 0x44 && p[i + 2] == 0x24) {
                const uint32_t off = *reinterpret_cast<const uint32_t*>(p + i + 4);
                if (off >= 0x100 && off < 0x4000) {
                    g_offMhController = static_cast<ptrdiff_t>(off);
                    Log("Radar POV: m_hController offset=0x%zx (schema rsp)",
                        static_cast<size_t>(g_offMhController));
                    return true;
                }
            }
        }
    }
    Log("Radar POV: m_hController offset not in schema xrefs; using default 0x%zx",
        static_cast<size_t>(g_offMhController));
    return g_offMhController > 0;
}

// Pure helper: mov edx,[rcx+m_hController]; resolve handle; return entity.
// Pattern from this client: 8B 91 D0 13 00 00 45 33 D2 83 FA FF ...
bool ResolveGetControllerFromPawn(const ModuleInfo& client)
{
    if (g_offMhController <= 0) {
        return false;
    }
    // Encode: mov edx, dword ptr [rcx + disp32]
    uint8_t pat[6] = {0x8B, 0x91, 0, 0, 0, 0};
    *reinterpret_cast<uint32_t*>(pat + 2) = static_cast<uint32_t>(g_offMhController);

    uintptr_t best = 0;
    size_t bestSize = 0x7fffffff;
    const uintptr_t base = reinterpret_cast<uintptr_t>(client.base);

    for (size_t i = 0; i + 16 < client.size; ++i) {
        if (memcmp(client.base + i, pat, 6) != 0) {
            continue;
        }
        // Prefer functions that *start* with this load (or INT3/ret immediately before).
        if (i > 0) {
            const uint8_t prev = client.base[i - 1];
            if (!(prev == 0xCC || prev == 0xC3 || prev == 0x90)) {
                continue;
            }
        }
        const uintptr_t fn = base + i;
        const size_t sz = ApproxFnSize(fn);
        // Pure resolve helpers are small (~0x50-0x80). Exclude large consumers.
        if (sz < 0x40 || sz > 0xA0) {
            continue;
        }
        // Pure helpers end with: mov rax, [rax] ; ret  (optionally test/je null before ret).
        // Reject helpers that then read another field (e.g. mov eax, [rax+imm]).
        const uint8_t* body = client.base + i;
        bool pureReturn = false;
        for (size_t j = 0x30; j + 4 < sz; ++j) {
            if (body[j] == 0x48 && body[j + 1] == 0x8B && body[j + 2] == 0x00) {
                // Immediate ret
                if (body[j + 3] == 0xC3) {
                    pureReturn = true;
                    break;
                }
                // test rax,rax ; je ; ret  OR  test rax,rax ; je ; mov rax,rcx ; ret
                if (body[j + 3] == 0x48 && body[j + 4] == 0x85 && body[j + 5] == 0xC0) {
                    // ensure no `mov e*x, [rax+imm]` in the next ~12 bytes after the load
                    bool fieldLoad = false;
                    for (size_t k = j + 3; k + 3 < sz && k < j + 16; ++k) {
                        if (body[k] == 0x8B && (body[k + 1] & 0xC7) == 0x40) { // mov r32, [rax+disp8]
                            fieldLoad = true;
                            break;
                        }
                        if (body[k] == 0x8B && (body[k + 1] & 0xC7) == 0x80) { // mov r32, [rax+disp32]
                            fieldLoad = true;
                            break;
                        }
                    }
                    if (!fieldLoad) {
                        pureReturn = true;
                        break;
                    }
                }
            }
        }
        if (!pureReturn) {
            continue;
        }
        // Extract entity-list global from: mov r64, [rip+disp] soon after cmp edx,-1
        for (size_t j = 6; j + 7 < 0x20 && j + 7 < sz; ++j) {
            // mov rcx/r8/... [rip+disp] is 48/4C 8B xx 05 ...
            if ((body[j] == 0x48 || body[j] == 0x4C) && body[j + 1] == 0x8B &&
                (body[j + 2] & 0xC7) == 0x05) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(body + j + 3);
                const uintptr_t globalAddr = fn + j + 7 + rel;
                if (IsInsideModule(client, globalAddr)) {
                    if (g_entityListGlobalSlot == 0) {
                        g_entityListGlobalSlot = globalAddr;
                    }
                    void* list = *reinterpret_cast<void**>(globalAddr);
                    if (list != nullptr && g_entityListChunks == nullptr) {
                        g_entityListChunks = reinterpret_cast<void**>(list);
                    }
                }
            }
        }
        if (sz < bestSize) {
            bestSize = sz;
            best = fn;
        }
    }

    if (best == 0) {
        Log("Radar POV: pure GetControllerFromPawn helper not found");
        return false;
    }

    // Re-extract entity list from the chosen function for reliability.
    {
        const uint8_t* body = reinterpret_cast<const uint8_t*>(best);
        const size_t sz = ApproxFnSize(best);
        for (size_t j = 6; j + 7 < 0x28 && j + 7 < sz; ++j) {
            if ((body[j] == 0x48 || body[j] == 0x4C) && body[j + 1] == 0x8B &&
                (body[j + 2] & 0xC7) == 0x05) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(body + j + 3);
                const uintptr_t globalAddr = best + j + 7 + rel;
                if (!IsInsideModule(client, globalAddr)) {
                    continue;
                }
                g_entityListGlobalSlot = globalAddr;
                void* list = *reinterpret_cast<void**>(globalAddr);
                if (list != nullptr) {
                    g_entityListChunks = reinterpret_cast<void**>(list);
                    Log("Radar POV: entity list chunks @ %p (from helper global %p)",
                        g_entityListChunks, reinterpret_cast<void*>(globalAddr));
                } else {
                    Log("Radar POV: entity list global @ %p is null at install (will retry on use)",
                        reinterpret_cast<void*>(globalAddr));
                }
                break;
            }
        }
    }

    g_getControllerFromPawn = reinterpret_cast<GetControllerFromPawnFn>(best);
    Log("Radar POV: GetControllerFromPawn @ %p size=0x%zx", reinterpret_cast<void*>(best),
        bestSize);
    return true;
}

bool ResolveRadarFunctions(const ModuleInfo& client)
{
    ResolveMhControllerOffset(client);

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

    // Tick: call mode; call intermediate; call players
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

    // players: getLocal, getSlot, getObs, getTeam, ... isEnemy ...
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

    uintptr_t getLocalFn = earlyUnique.size() >= 1 ? earlyUnique[0] : 0;
    uintptr_t getObsFn = earlyUnique.size() >= 3 ? earlyUnique[2] : 0;

    // Sanity: getLocal is tiny (~0x30-0x40), getObs medium.
    if (getLocalFn != 0) {
        const size_t sz = ApproxFnSize(getLocalFn);
        if (sz > 0x80) {
            Log("Radar POV: getLocal candidate size 0x%zx looks large; still trying", sz);
        }
    }
    if (getObsFn != 0) {
        // getObs body contains imm 0x1220
        const uint8_t* body = reinterpret_cast<const uint8_t*>(getObsFn);
        bool has1220 = false;
        for (size_t i = 0; i + 4 < 0x40; ++i) {
            if (body[i] == 0x20 && body[i + 1] == 0x12 && body[i + 2] == 0x00 &&
                body[i + 3] == 0x00) {
                has1220 = true;
                break;
            }
        }
        if (!has1220) {
            Log("Radar POV: getObs candidate @ %p lacks +0x1220; scanning early calls",
                reinterpret_cast<void*>(getObsFn));
            getObsFn = 0;
            for (uintptr_t c : earlyUnique) {
                if (c == getLocalFn) {
                    continue;
                }
                const uint8_t* b = reinterpret_cast<const uint8_t*>(c);
                for (size_t i = 0; i + 4 < 0x40; ++i) {
                    if (b[i] == 0x20 && b[i + 1] == 0x12 && b[i + 2] == 0x00 && b[i + 3] == 0x00) {
                        getObsFn = c;
                        break;
                    }
                }
                if (getObsFn != 0) {
                    break;
                }
            }
        }
    }

    if (getLocalFn == 0 || getObsFn == 0) {
        Log("Radar POV: helpers incomplete (getLocal=%p getObs=%p)",
            reinterpret_cast<void*>(getLocalFn), reinterpret_cast<void*>(getObsFn));
        // Mode+players only still clears show-all (safe partial).
    } else {
        Log("Radar POV: helpers getLocal=%p getObs=%p", reinterpret_cast<void*>(getLocalFn),
            reinterpret_cast<void*>(getObsFn));
    }

    // Pure pawn->controller + entity list.
    if (!ResolveGetControllerFromPawn(client)) {
        Log("Radar POV: will use inline handle resolve if entity list is known");
    }

    // If entity list still null, pull from getObs-adjacent getTeam or getPawn helper.
    if (g_entityListChunks == nullptr && earlyUnique.size() >= 4) {
        // earlyUnique[3] is often getTeam which loads entity list the same way.
        const uintptr_t getTeamFn = earlyUnique[3];
        const uint8_t* body = reinterpret_cast<const uint8_t*>(getTeamFn);
        const size_t sz = ApproxFnSize(getTeamFn);
        for (size_t j = 0; j + 7 < sz && j < 0x30; ++j) {
            if ((body[j] == 0x48 || body[j] == 0x4C) && body[j + 1] == 0x8B &&
                (body[j + 2] & 0xC7) == 0x05) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(body + j + 3);
                const uintptr_t globalAddr = getTeamFn + j + 7 + rel;
                if (!IsInsideModule(client, globalAddr)) {
                    continue;
                }
                g_entityListGlobalSlot = globalAddr;
                void* list = *reinterpret_cast<void**>(globalAddr);
                if (list != nullptr) {
                    g_entityListChunks = reinterpret_cast<void**>(list);
                }
                Log("Radar POV: entity list from getTeam global @ %p -> %p",
                    reinterpret_cast<void*>(globalAddr), g_entityListChunks);
                break;
            }
        }
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

    // Core true-POV: redirect getLocal → observed controller during radar update.
    if (getLocalTarget != nullptr && g_getObserverTarget != nullptr) {
        if (!CreateAndEnableHook(getLocalTarget, reinterpret_cast<void*>(&Hook_GetLocal),
                                 reinterpret_cast<void**>(&g_origGetLocal), "getLocal")) {
            Log("Radar POV: getLocal hook failed — falling back to show-all clear only");
            g_origGetLocal = reinterpret_cast<GetLocalFn>(getLocalTarget);
        }
    } else {
        Log("Radar POV: getLocal/getObs unresolved — show-all clear only (not full POV)");
    }

    g_installed.store(true, std::memory_order_release);
    Log("Radar POV: installed (enabled=%d getLocal=%d getObs=%d ctrlFromPawn=%d entityList=%d "
        "m_hController=0x%zx)",
        g_enabled.load() ? 1 : 0,
        g_origGetLocal != nullptr ? 1 : 0,
        g_getObserverTarget != nullptr ? 1 : 0,
        g_getControllerFromPawn != nullptr ? 1 : 0,
        g_entityListChunks != nullptr ? 1 : 0,
        static_cast<size_t>(g_offMhController));
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
    g_getControllerFromPawn = nullptr;
    g_entityListChunks = nullptr;
    g_entityListGlobalSlot = 0;
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
    Log("Radar POV: aggressive_redirects=%d (legacy flag; true POV uses getLocal redirect)",
        enabled ? 1 : 0);
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
    queueCmd("cl_radar_show_all_players_when_spectating 0");
    queueCmd("cl_radar_square_when_spectating 0");
}
