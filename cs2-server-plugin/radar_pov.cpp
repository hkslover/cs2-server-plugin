#include "radar_pov.h"

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

// =============================================================================
// Design (Ghidra-backed): identity rewrite + teammate type + force ARGB
//
// Hooks (7):
//   radar_update, getLocal, GetEntityBySlot, demo/HLTV, findPlayerBySlot,
//   SetRadarIconType (teammate 0x11→9/0xD), RadarIconColor (force cl_teammate_color_*)
// Colour-gate hooks (863200 / 8494d0) removed — force-color covers them.
// =============================================================================

RadarPovLogFn g_log = nullptr;
std::atomic<bool> g_enabled{true};
std::atomic<bool> g_installed{false};

thread_local int g_inRadarUpdate = 0;
thread_local void* g_povSelfPawn = nullptr;
thread_local bool g_povActive = false;
thread_local int g_spectatorSlot = -1;
thread_local int g_povSelfSlot = -1;
// Observed player's m_iTeamNum (2=CT, 3=T). Competitive colours are teammates only.
thread_local int g_povSelfTeam = 0;

std::atomic<int> g_faultRadarUpdate{0};
std::atomic<int> g_faultGetLocal{0};
std::atomic<int> g_faultResolve{0};
std::atomic<int> g_logPovOk{0};
std::atomic<int> g_logPovFail{0};
std::atomic<int> g_logSpectatorFilter{0};
std::atomic<int> g_logDemoStateOverride{0};
std::atomic<int> g_logGetEntityBySlot{0};
std::atomic<int> g_logIconType{0};
std::atomic<int> g_logForceColor{0};
std::atomic<int> g_logForceColorSkip{0};

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

uint32_t GetPeTimestamp(const ModuleInfo& mod)
{
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
    // Radar update wrapper: test dl,dl
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
// Types — only identity / demo / scope
// ---------------------------------------------------------------------------

using RadarUpdateFn = void(__fastcall*)(void* updateContext, uint8_t updateEnabled);
using RadarDemoStateFn = uint8_t(__fastcall*)(void* engineState);
using GetLocalFn = void*(__fastcall*)();
using GetObserverTargetFn = void*(__fastcall*)(void* localPawn);
using GetPlayerSlotFn = void(__fastcall*)(void* pawn, int* outSlot);
using FindPlayerBySlotFn = void*(__fastcall*)(int slot);
// Controller-by-slot; icon colour path hardcodes GetEntityBySlot(0) as "local".
using GetEntityBySlotFn = void*(__fastcall*)(int slot);
// FUN_180e39320(icon, playerTeam) — writes icon type at +0x16c.
using SetRadarIconTypeFn = void(__fastcall*)(void* icon, int playerTeam);
// FUN_180e460e0(radar, icon) — icon colour update.
using RadarIconColorFn = void(__fastcall*)(void* radar, void* icon);
// FUN_180849370(outArgb, colorIndex) — cl_teammate_color_N ARGB.
using GetCompColorArgbFn = uint32_t*(__fastcall*)(uint32_t* outArgb, int colorIndex);
// FUN_180a732c0(playerIndex) — resolve entity/controller for icon subject.
using ResolvePlayerByIndexFn = void*(__fastcall*)(int playerIndex);

RadarUpdateFn g_origRadarUpdate = nullptr;
RadarDemoStateFn g_origRadarDemoState = nullptr;
GetLocalFn g_origGetLocal = nullptr;
GetObserverTargetFn g_getObserverTarget = nullptr;
GetPlayerSlotFn g_getPlayerSlot = nullptr;
FindPlayerBySlotFn g_origFindPlayerBySlot = nullptr;
GetEntityBySlotFn g_origGetEntityBySlot = nullptr;
SetRadarIconTypeFn g_origSetRadarIconType = nullptr;
RadarIconColorFn g_origRadarIconColor = nullptr;
GetCompColorArgbFn g_getCompColorArgb = nullptr;
ResolvePlayerByIndexFn g_resolvePlayerByIndex = nullptr;

bool g_minhookInitialized = false;
bool g_spectatorFilterHooked = false;
bool g_getEntityBySlotHooked = false;
bool g_iconTypeHooked = false;
bool g_iconColorHooked = false;
uintptr_t g_radarDemoStateGlobalSlot = 0;

constexpr size_t kIsPlayerPawnVtableByteOff = 0x4D8;
constexpr size_t kIsObserverVtableByteOff = 0xAA0;
constexpr ptrdiff_t kPawnObserverServices = 0x1220;
constexpr ptrdiff_t kRadarFromUpdateContext = -0x20;
constexpr ptrdiff_t kIconTypeOffset = 0x16c;
constexpr ptrdiff_t kIconPlayerIndexOffset = 0x158;
constexpr ptrdiff_t kIconColorTimeOffset = 0x14c;
constexpr ptrdiff_t kControllerTeamOffset = 0x3E7;
constexpr ptrdiff_t kCompTeammateColorOffset = 0x850;
constexpr size_t kPanelGetStyleVOff = 0x230;
constexpr size_t kStyleSetColorVOff = 0x188;
constexpr int kIconTypeLiveTeammate = 0x11;
constexpr int kIconTypeT = 9;
constexpr int kIconTypeCT = 0xd;
constexpr int kTeamT = 3;
constexpr int kTeamCT = 2;
// Same panels FUN_180e460e0 paints for competitive ARGB (T then CT sets).
constexpr ptrdiff_t kCompColorPanelOffs[] = {0x60, 0x68, 0x70, 0x80, 0x88, 0x90};
ptrdiff_t g_radarShowAllFlagOffset = 0;

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
    if (radar == nullptr || g_radarShowAllFlagOffset <= 0) {
        return;
    }
    auto* flags = reinterpret_cast<uint8_t*>(radar) + g_radarShowAllFlagOffset;
    if (showAll) {
        *flags = static_cast<uint8_t>(*flags | static_cast<uint8_t>(1));
    } else {
        *flags = static_cast<uint8_t>(*flags & ~static_cast<uint8_t>(1));
    }
}

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
    __try {
        void* services =
            *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(localPawn) + kPawnObserverServices);
        return services != nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

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
    if (!IsPlayerPawn(target)) {
        if (g_logPovFail.fetch_add(1) == 0) {
            Log("Radar POV: getObs returned non-pawn %p (rejected)", target);
        }
        return nullptr;
    }
    return target;
}

// ---------------------------------------------------------------------------
// Detours (upstream only)
// ---------------------------------------------------------------------------

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

    if (!g_enabled.load(std::memory_order_relaxed) || g_inRadarUpdate <= 0 || !g_povActive) {
        return real;
    }
    return g_povSelfPawn != nullptr ? g_povSelfPawn : real;
}

// Icon colour / spectator checks use GetEntityBySlot(0), not getLocal.
// Remap demo freecam slot 0 (and -1 = local slot) to the observed player.
void* __fastcall Hook_GetEntityBySlot(int slot)
{
    if (g_origGetEntityBySlot == nullptr) {
        return nullptr;
    }
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        g_povSelfSlot >= 0 && (slot == 0 || slot == -1)) {
        const int n = g_logGetEntityBySlot.fetch_add(1);
        if (n == 0) {
            Log("Radar POV: GetEntityBySlot %d -> observed slot %d", slot, g_povSelfSlot);
        }
        return g_origGetEntityBySlot(g_povSelfSlot);
    }
    return g_origGetEntityBySlot(slot);
}

// m_iTeamNum @ +0x3E7 on pawn and controller (engine uses this in e328a0 / 85b540).
int ReadEntityTeam(void* ent)
{
    if (ent == nullptr) {
        return 0;
    }
    __try {
        return static_cast<unsigned char>(
            *(reinterpret_cast<uint8_t*>(ent) + kControllerTeamOffset));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// Refresh observed team: pawn first (reliable in demos), then controller slot.
int RefreshPovSelfTeam()
{
    int team = ReadEntityTeam(g_povSelfPawn);
    if (team != kTeamT && team != kTeamCT && g_origGetEntityBySlot != nullptr &&
        g_povSelfSlot >= 0) {
        void* ctrl = nullptr;
        __try {
            ctrl = g_origGetEntityBySlot(g_povSelfSlot);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ctrl = nullptr;
        }
        team = ReadEntityTeam(ctrl);
    }
    if (team == kTeamT || team == kTeamCT) {
        g_povSelfTeam = team;
    }
    return g_povSelfTeam;
}

// True only for same T/CT as the observed player (never spectators / enemies).
bool IsPovTeammateTeam(int playerTeam)
{
    if (playerTeam != kTeamT && playerTeam != kTeamCT) {
        return false;
    }
    int selfTeam = g_povSelfTeam;
    if (selfTeam != kTeamT && selfTeam != kTeamCT) {
        selfTeam = RefreshPovSelfTeam();
    }
    if (selfTeam != kTeamT && selfTeam != kTeamCT) {
        return false;
    }
    return playerTeam == selfTeam;
}

void PreparePovContext()
{
    g_povSelfPawn = nullptr;
    g_povActive = false;
    g_spectatorSlot = -1;
    g_povSelfSlot = -1;
    g_povSelfTeam = 0;

    if (g_origGetLocal == nullptr || g_getObserverTarget == nullptr) {
        return;
    }

    void* realPawn = nullptr;
    __try {
        realPawn = g_origGetLocal();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        realPawn = nullptr;
    }
    void* povPawn = ResolvePovSelfPawn(realPawn);
    if (povPawn == nullptr) {
        if (g_logPovFail.fetch_add(1) == 0) {
            Log("Radar POV: no observer target yet — show-all ON (fail-safe) local=%p", realPawn);
        }
        return;
    }

    g_povSelfPawn = povPawn;
    g_povActive = true;
    if (g_getPlayerSlot != nullptr) {
        int spectatorSlot = -1;
        int povSlot = -1;
        __try {
            g_getPlayerSlot(realPawn, &spectatorSlot);
            g_getPlayerSlot(povPawn, &povSlot);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            spectatorSlot = -1;
            povSlot = -1;
        }
        if (spectatorSlot >= 0 && spectatorSlot != povSlot) {
            g_spectatorSlot = spectatorSlot;
        }
        if (povSlot >= 0) {
            g_povSelfSlot = povSlot;
        }
    }
    RefreshPovSelfTeam();
    if (g_logPovOk.fetch_add(1) == 0) {
        Log("Radar POV: active — pawn %p -> observed %p (slot %d team %d, spectatorSlot %d)",
            realPawn, povPawn, g_povSelfSlot, g_povSelfTeam, g_spectatorSlot);
    }
}

void ClearPovContext()
{
    g_povSelfPawn = nullptr;
    g_povActive = false;
    g_spectatorSlot = -1;
    g_povSelfSlot = -1;
    g_povSelfTeam = 0;
}

void __fastcall Hook_RadarUpdate(void* updateContext, uint8_t updateEnabled)
{
    const bool wantPov = g_enabled.load(std::memory_order_relaxed);
    auto* radar = reinterpret_cast<uint8_t*>(updateContext) + kRadarFromUpdateContext;
    if (wantPov) {
        ++g_inRadarUpdate;
        PreparePovContext();
        SetShowAllFlag(radar, !g_povActive);
    }

    __try {
        if (g_origRadarUpdate != nullptr) {
            g_origRadarUpdate(updateContext, updateEnabled);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_faultRadarUpdate.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in Hook_RadarUpdate (code=0x%08lX) context=%p",
                GetExceptionCode(), updateContext);
        }
    }

    if (wantPov) {
        SetShowAllFlag(radar, !g_povActive);
        if (g_inRadarUpdate > 0) {
            --g_inRadarUpdate;
        }
        ClearPovContext();
    }
}

uint8_t __fastcall Hook_RadarDemoState(void* engineState)
{
    uint8_t result = 0;
    if (g_origRadarDemoState != nullptr) {
        result = g_origRadarDemoState(engineState);
    }
    if (g_inRadarUpdate > 0 && g_povActive) {
        if (g_logDemoStateOverride.fetch_add(1) == 0) {
            Log("Radar POV: demo/HLTV state %u -> 0 for radar frame",
                static_cast<unsigned>(result));
        }
        return 0;
    }
    return result;
}

void* __fastcall Hook_FindPlayerBySlot(int slot)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        g_spectatorSlot >= 0 && slot == g_spectatorSlot) {
        if (g_logSpectatorFilter.fetch_add(1) == 0) {
            Log("Radar POV: filtering demo spectator slot %d", slot);
        }
        return nullptr;
    }
    return g_origFindPlayerBySlot != nullptr ? g_origFindPlayerBySlot(slot) : nullptr;
}

// FUN_180e39320: with live identity, same-team non-self icons become type 0x11.
// FUN_180e460e0 live RGB only paints types 9 / 0xD. Map 0x11 → team panel type
// for POV teammates only (never rewrite enemy icons).
void __fastcall Hook_SetRadarIconType(void* icon, int playerTeam)
{
    if (g_origSetRadarIconType != nullptr) {
        g_origSetRadarIconType(icon, playerTeam);
    }
    if (!g_enabled.load(std::memory_order_relaxed) || g_inRadarUpdate <= 0 || !g_povActive ||
        icon == nullptr || !IsPovTeammateTeam(playerTeam)) {
        return;
    }
    __try {
        auto* typePtr =
            reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(icon) + kIconTypeOffset);
        if (*typePtr != kIconTypeLiveTeammate) {
            return;
        }
        const int fixed = (playerTeam == kTeamT) ? kIconTypeT : kIconTypeCT;
        *typePtr = fixed;
        if (g_logIconType.fetch_add(1) == 0) {
            Log("Radar POV: icon type 0x11 -> %d (teammate team %d, self team %d)", fixed,
                playerTeam, g_povSelfTeam);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // ignore
    }
}

bool SetIconPanelColor(void* icon, ptrdiff_t panelOff, uint32_t* argb)
{
    if (icon == nullptr || argb == nullptr) {
        return false;
    }
    __try {
        void* panel = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(icon) + panelOff);
        if (panel == nullptr) {
            return false;
        }
        void* inner = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(panel) + 8);
        if (inner == nullptr) {
            return false;
        }
        void** vt = *reinterpret_cast<void***>(inner);
        if (vt == nullptr) {
            return false;
        }
        using GetStyleFn = void*(__fastcall*)(void*);
        auto getStyle = reinterpret_cast<GetStyleFn>(vt[kPanelGetStyleVOff / sizeof(void*)]);
        if (getStyle == nullptr) {
            return false;
        }
        void* style = getStyle(inner);
        if (style == nullptr) {
            return false;
        }
        void** svt = *reinterpret_cast<void***>(style);
        if (svt == nullptr) {
            return false;
        }
        using SetColorFn = void(__fastcall*)(void*, uint32_t*);
        auto setColor = reinterpret_cast<SetColorFn>(svt[kStyleSetColorVOff / sizeof(void*)]);
        if (setColor == nullptr) {
            return false;
        }
        setColor(style, argb);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// After native e460e0: ensure competitive ARGB is on the icon body panels.
// Demo netvars / gates often leave native paint as a no-op even when types are fixed.
void ForceCompetitiveIconColor(void* icon)
{
    if (icon == nullptr || g_getCompColorArgb == nullptr || !g_povActive) {
        return;
    }
    __try {
        const int type =
            *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(icon) + kIconTypeOffset);
        // Teammate body types only (after rewrite: 9/0xD; tolerate 0x11 if rewrite missed).
        if (type != kIconTypeT && type != kIconTypeCT && type != kIconTypeLiveTeammate) {
            return;
        }

        const int playerIndex =
            *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(icon) + kIconPlayerIndexOffset);

        void* controller = nullptr;
        if (g_resolvePlayerByIndex != nullptr && playerIndex != -1) {
            controller = g_resolvePlayerByIndex(playerIndex);
        }
        // Fallback: treat index as slot (often works in demos).
        if (controller == nullptr && g_origGetEntityBySlot != nullptr && playerIndex >= 0 &&
            playerIndex < 64) {
            controller = g_origGetEntityBySlot(playerIndex);
        }
        if (controller == nullptr) {
            if (g_logForceColorSkip.fetch_add(1) == 0) {
                Log("Radar POV: force-color skip — no controller (playerIndex=%d type=%d)",
                    playerIndex, type);
            }
            return;
        }

        int playerTeam = ReadEntityTeam(controller);
        // Engine passes subject team into SetRadarIconType; controller netvar can lag.
        // Prefer a valid T/CT team for filtering.
        if (playerTeam != kTeamT && playerTeam != kTeamCT) {
            // Infer from icon type we (or native) assigned: 9=T, 0xD=CT.
            if (type == kIconTypeT) {
                playerTeam = kTeamT;
            } else if (type == kIconTypeCT) {
                playerTeam = kTeamCT;
            }
        }
        // Competitive palette is teammates only; enemies stay native red/default.
        if (!IsPovTeammateTeam(playerTeam)) {
            return;
        }

        int colorIdx = *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(controller) +
                                                kCompTeammateColorOffset);
        const int rawNetvar = colorIdx;
        if (colorIdx < 0 || colorIdx > 4) {
            // Stable distinct fallback when demo leaves netvar unset.
            colorIdx = playerIndex >= 0 ? (playerIndex % 5) : 0;
        }

        uint32_t argb = 0;
        g_getCompColorArgb(&argb, colorIdx);
        if (argb == 0) {
            if (g_logForceColorSkip.fetch_add(1) == 0) {
                Log("Radar POV: force-color skip — ARGB=0 idx=%d", colorIdx);
            }
            return;
        }

        int painted = 0;
        for (ptrdiff_t off : kCompColorPanelOffs) {
            if (SetIconPanelColor(icon, off, &argb)) {
                ++painted;
            }
        }

        const int n = g_logForceColor.fetch_add(1);
        if (n == 0 || n == 10 || n == 50) {
            Log("Radar POV: force-color teammate type=%d team=%d selfTeam=%d netvar=%d idx=%d "
                "argb=0x%08X panels=%d playerIndex=%d",
                type, playerTeam, g_povSelfTeam, rawNetvar, colorIdx, argb, painted, playerIndex);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_logForceColorSkip.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in ForceCompetitiveIconColor");
        }
    }
}

void __fastcall Hook_RadarIconColor(void* radar, void* icon)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        icon != nullptr) {
        __try {
            // Defeat per-icon rate-limit in the live colour branch.
            *reinterpret_cast<float*>(reinterpret_cast<uint8_t*>(icon) + kIconColorTimeOffset) =
                -1.0e6f;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // ignore
        }
    }

    if (g_origRadarIconColor != nullptr) {
        g_origRadarIconColor(radar, icon);
    }

    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive) {
        ForceCompetitiveIconColor(icon);
    }
}

// ---------------------------------------------------------------------------
// Resolution
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
    g_radarDemoStateGlobalSlot = 0;
    g_radarShowAllFlagOffset = 0;

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
            continue;
        }
        radarModeFn = fn;
        modeCallSite = callSites[0];
        Log("Radar POV: radar mode fn @ %p (E8 callers=%zu, size 0x%zx)",
            reinterpret_cast<void*>(radarModeFn), callSites.size(), ApproxFnSize(fn));
        break;
    }
    if (radarModeFn == 0 || modeCallSite == 0) {
        Log("Radar POV: radar mode function not found");
        return false;
    }

    for (size_t i = 0; i + 7 <= ApproxFnSize(radarModeFn); ++i) {
        const uint8_t* b = reinterpret_cast<const uint8_t*>(radarModeFn + i);
        if (b[0] == 0x80 && b[1] == 0xA3 && b[6] == 0xFE) {
            g_radarShowAllFlagOffset =
                static_cast<ptrdiff_t>(*reinterpret_cast<const uint32_t*>(b + 2));
            break;
        }
    }
    if (g_radarShowAllFlagOffset <= 0) {
        Log("Radar POV: show-all flag offset not found");
        return false;
    }
    Log("Radar POV: show-all flag offset=0x%zx", static_cast<size_t>(g_radarShowAllFlagOffset));

    const uintptr_t radarUpdateFn = FindFunctionStart(client, modeCallSite);
    const auto* updateBytes = reinterpret_cast<const uint8_t*>(radarUpdateFn);
    const bool validRadarUpdate = radarUpdateFn != 0 && radarUpdateFn != radarModeFn &&
        updateBytes[0] == 0x84 && updateBytes[1] == 0xD2 && updateBytes[0x23] == 0x48 &&
        updateBytes[0x24] == 0x8D && updateBytes[0x25] == 0x71 && updateBytes[0x26] == 0xE0;
    if (!validRadarUpdate) {
        Log("Radar POV: full radar update wrapper shape not recognized");
        return false;
    }
    Log("Radar POV: full radar update fn @ %p size=0x%zx", reinterpret_cast<void*>(radarUpdateFn),
        ApproxFnSize(radarUpdateFn));

    // demo/HLTV: mov rcx,[rip+global]; mov rax,[rcx]; call [rax+2B0h]
    for (size_t i = 0; i + 15 < ApproxFnSize(radarModeFn); ++i) {
        const uint8_t* b = reinterpret_cast<const uint8_t*>(radarModeFn + i);
        if (b[0] != 0x48 || b[1] != 0x8B || b[2] != 0x0D || b[7] != 0x48 || b[8] != 0x8B ||
            b[9] != 0x01 || b[10] != 0xFF || b[11] != 0x90 || b[12] != 0xB0 || b[13] != 0x02 ||
            b[14] != 0x00 || b[15] != 0x00) {
            continue;
        }
        const int32_t rel = *reinterpret_cast<const int32_t*>(b + 3);
        const uintptr_t slot = radarModeFn + i + 7 + static_cast<intptr_t>(rel);
        if (IsInsideModule(client, slot)) {
            g_radarDemoStateGlobalSlot = slot;
            break;
        }
    }
    if (g_radarDemoStateGlobalSlot == 0) {
        Log("Radar POV: native demo/HLTV state predicate not found");
        return false;
    }
    Log("Radar POV: demo/HLTV state global @ %p",
        reinterpret_cast<void*>(g_radarDemoStateGlobalSlot));

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
        Log("Radar POV: radar players fn @ %p size=0x%zx", reinterpret_cast<void*>(radarPlayersFn),
            ApproxFnSize(radarPlayersFn));
    }
    if (radarPlayersFn == 0) {
        Log("Radar POV: radar players function not found");
        return false;
    }

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
    uintptr_t getPlayerSlotFn = 0;
    uintptr_t findPlayerBySlotFn = 0;

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
    if (getObsFn == 0 && earlyUnique.size() >= 3) {
        getObsFn = earlyUnique[2];
    }

    {
        const uint8_t* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
        const size_t bodySize = ApproxFnSize(radarPlayersFn);
        for (size_t i = 0; i + 13 < bodySize && i < 0x100; ++i) {
            if (body[i] != 0x48 || body[i + 1] != 0x8D || body[i + 2] != 0x54 ||
                body[i + 3] != 0x24 || body[i + 4] != 0x24 || body[i + 5] != 0x48 ||
                body[i + 6] != 0x8B || body[i + 7] != 0xC8 || body[i + 8] != 0xE8) {
                continue;
            }
            DecodeRel32Call(body + i + 8, radarPlayersFn + i + 8, getPlayerSlotFn);
            break;
        }
    }

    {
        const uint8_t* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
        const size_t bodySize = ApproxFnSize(radarPlayersFn);
        for (size_t i = 0; i + 18 < bodySize; ++i) {
            if (body[i] != 0x8B || body[i + 1] != 0xCF || body[i + 2] != 0xE8 ||
                body[i + 7] != 0x48 || body[i + 8] != 0x89 || body[i + 9] != 0x44 ||
                body[i + 10] != 0x24 || body[i + 11] != 0x58 || body[i + 12] != 0x48 ||
                body[i + 13] != 0x8B || body[i + 14] != 0xD8 || body[i + 15] != 0x48 ||
                body[i + 16] != 0x85 || body[i + 17] != 0xC0) {
                continue;
            }
            DecodeRel32Call(body + i + 2, radarPlayersFn + i + 2, findPlayerBySlotFn);
            break;
        }
    }

    Log("Radar POV: helpers getLocal=%p size=0x%zx getSlot=%p getObs=%p size=0x%zx "
        "findPlayerBySlot=%p",
        reinterpret_cast<void*>(getLocalFn), getLocalFn ? ApproxFnSize(getLocalFn) : 0,
        reinterpret_cast<void*>(getPlayerSlotFn), reinterpret_cast<void*>(getObsFn),
        getObsFn ? ApproxFnSize(getObsFn) : 0, reinterpret_cast<void*>(findPlayerBySlotFn));

    if (getLocalFn == 0 || getObsFn == 0) {
        Log("Radar POV: helpers incomplete (getLocal=%p getObs=%p)",
            reinterpret_cast<void*>(getLocalFn), reinterpret_cast<void*>(getObsFn));
        return false;
    }

    // GetEntityBySlot (FUN_180926920): controller array by slot.
    // Unique body ends with mov rax,[rcx+rax*8]; add rsp,28h; ret
    // Prefer caller chain from icon renderer if we can find IsSpectatorCheck first.
    {
        auto looksLikeGetEntityBySlot = [&](uintptr_t fn) -> bool {
            if (!IsInsideModule(client, fn)) {
                return false;
            }
            const auto* p = reinterpret_cast<const uint8_t*>(fn);
            return p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC && p[3] == 0x28 && p[4] == 0x83 &&
                p[5] == 0xF9 && p[6] == 0xFF && p[7] == 0x75 && p[8] == 0x17 && p[24] == 0xFF &&
                p[25] == 0x90 && p[26] == 0x10 && p[27] == 0x03 && p[28] == 0x00 && p[29] == 0x00 &&
                p[42] == 0x48 && p[43] == 0x8B && p[44] == 0x04 && p[45] == 0xC1 && p[46] == 0x48 &&
                p[47] == 0x83 && p[48] == 0xC4 && p[49] == 0x28 && p[50] == 0xC3;
        };

        // IsSpectatorCheck prologue+team-cmp — used only to find GetEntityBySlot call chain.
        uintptr_t isSpecFn = 0;
        if (client.base != nullptr && client.size >= 32) {
            for (size_t i = 0; i + 32 <= client.size; ++i) {
                const uint8_t* p = client.base + i;
                if (p[0] != 0x48 || p[1] != 0x89 || p[2] != 0x5C || p[3] != 0x24 || p[4] != 0x08 ||
                    p[5] != 0x57 || p[6] != 0x48 || p[7] != 0x83 || p[8] != 0xEC || p[9] != 0x20 ||
                    p[10] != 0x48 || p[11] != 0x8B || p[12] != 0xD9 || p[13] != 0x48 ||
                    p[14] != 0x8D || p[15] != 0x0D || p[20] != 0xE8 || p[25] != 0x80 ||
                    p[26] != 0xBB || p[27] != 0xE7 || p[28] != 0x03 || p[29] != 0x00 ||
                    p[30] != 0x00 || p[31] != 0x01) {
                    continue;
                }
                isSpecFn = reinterpret_cast<uintptr_t>(p);
                break;
            }
        }

        if (isSpecFn != 0 && client.base != nullptr) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(client.base);
            for (size_t i = 0; i + 5 < client.size; ++i) {
                if (client.base[i] != 0xE8) {
                    continue;
                }
                uintptr_t target = 0;
                if (!DecodeRel32Call(client.base + i, base + i, target) || target != isSpecFn) {
                    continue;
                }
                const size_t callOff = i;
                const size_t backStart = callOff > 0x40 ? callOff - 0x40 : 0;
                for (size_t j = backStart; j + 7 < callOff; ++j) {
                    if (client.base[j] != 0x33 || client.base[j + 1] != 0xC9) {
                        continue;
                    }
                    for (size_t k = j; k + 5 < callOff; ++k) {
                        uintptr_t getEnt = 0;
                        if (!DecodeRel32Call(client.base + k, base + k, getEnt)) {
                            continue;
                        }
                        if (getEnt == isSpecFn || !looksLikeGetEntityBySlot(getEnt)) {
                            continue;
                        }
                        g_origGetEntityBySlot = reinterpret_cast<GetEntityBySlotFn>(getEnt);
                        Log("Radar POV: GetEntityBySlot @ %p (via icon-renderer call chain)",
                            reinterpret_cast<void*>(getEnt));
                        break;
                    }
                    if (g_origGetEntityBySlot != nullptr) {
                        break;
                    }
                }
                if (g_origGetEntityBySlot != nullptr) {
                    break;
                }
            }
        }

        if (g_origGetEntityBySlot == nullptr && client.base != nullptr) {
            std::vector<uintptr_t> hits;
            for (size_t i = 0; i + 0x33 <= client.size; ++i) {
                const uintptr_t addr = reinterpret_cast<uintptr_t>(client.base + i);
                if (looksLikeGetEntityBySlot(addr)) {
                    hits.push_back(addr);
                }
            }
            // Prefer the controller-array helper used by radar (first in image is 0x926920).
            if (!hits.empty()) {
                g_origGetEntityBySlot = reinterpret_cast<GetEntityBySlotFn>(hits[0]);
                Log("Radar POV: GetEntityBySlot @ %p (body mask, %zu candidates)",
                    reinterpret_cast<void*>(hits[0]), hits.size());
            }
        }

        if (g_origGetEntityBySlot == nullptr) {
            Log("Radar POV: GetEntityBySlot not found — colours may stay team-based");
        }
    }

    // FUN_180e39320 — 40 56 57 41 56 48 83 EC 20 8B FA 4C 8B F1 E8 <getLocal>
    {
        constexpr size_t kCallGetLocalOff = 14;
        auto looksLike = [&](uintptr_t fn) -> bool {
            if (!IsInsideModule(client, fn)) {
                return false;
            }
            const auto* p = reinterpret_cast<const uint8_t*>(fn);
            return p[0] == 0x40 && p[1] == 0x56 && p[2] == 0x57 && p[3] == 0x41 && p[4] == 0x56 &&
                p[5] == 0x48 && p[6] == 0x83 && p[7] == 0xEC && p[8] == 0x20 && p[9] == 0x8B &&
                p[10] == 0xFA && p[11] == 0x4C && p[12] == 0x8B && p[13] == 0xF1 && p[14] == 0xE8;
        };
        if (radarPlayersFn != 0 && getLocalFn != 0) {
            const auto* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
            const size_t bodySize = ApproxFnSize(radarPlayersFn);
            for (size_t i = 0; i + 5 < bodySize; ++i) {
                uintptr_t target = 0;
                if (!DecodeRel32Call(body + i, radarPlayersFn + i, target) || !looksLike(target)) {
                    continue;
                }
                uintptr_t first = 0;
                if (DecodeRel32Call(reinterpret_cast<const uint8_t*>(target) + kCallGetLocalOff,
                                    target + kCallGetLocalOff, first) &&
                    first == getLocalFn) {
                    g_origSetRadarIconType = reinterpret_cast<SetRadarIconTypeFn>(target);
                    Log("Radar POV: SetRadarIconType @ %p", reinterpret_cast<void*>(target));
                    break;
                }
            }
        }
        if (g_origSetRadarIconType == nullptr) {
            Log("Radar POV: SetRadarIconType not found — live type 0x11 may block RGB");
        }
    }

    // FUN_180849370 — cl_teammate_color_N ARGB
    {
        const uint8_t kPat[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9,
                                0x83, 0xFA, 0xFF, 0x7D};
        const uint8_t* hit = FindBytes(client.base, client.size, kPat, sizeof(kPat));
        if (hit != nullptr) {
            g_getCompColorArgb =
                reinterpret_cast<GetCompColorArgbFn>(reinterpret_cast<uintptr_t>(hit));
            Log("Radar POV: GetCompColorArgb @ %p", hit);
        }
    }

    // FUN_180e460e0 + ResolvePlayerByIndex via IsSpectatorCheck/GetEntityBySlot call chain
    if (g_origGetEntityBySlot != nullptr && client.base != nullptr) {
        // Locate IsSpectatorCheck for xref (same mask as earlier)
        uintptr_t isSpecFn = 0;
        for (size_t i = 0; i + 32 <= client.size; ++i) {
            const uint8_t* p = client.base + i;
            if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24 && p[4] == 0x08 &&
                p[5] == 0x57 && p[6] == 0x48 && p[7] == 0x83 && p[8] == 0xEC && p[9] == 0x20 &&
                p[10] == 0x48 && p[11] == 0x8B && p[12] == 0xD9 && p[25] == 0x80 && p[26] == 0xBB &&
                p[27] == 0xE7) {
                isSpecFn = reinterpret_cast<uintptr_t>(p);
                break;
            }
        }
        if (isSpecFn != 0) {
            const uintptr_t getEnt = reinterpret_cast<uintptr_t>(g_origGetEntityBySlot);
            const uintptr_t base = reinterpret_cast<uintptr_t>(client.base);
            for (size_t i = 0; i + 5 < client.size; ++i) {
                if (client.base[i] != 0xE8) {
                    continue;
                }
                uintptr_t t = 0;
                if (!DecodeRel32Call(client.base + i, base + i, t) || t != isSpecFn) {
                    continue;
                }
                bool sawGetEnt = false;
                const size_t backStart = i > 0x40 ? i - 0x40 : 0;
                for (size_t j = backStart; j + 5 < i; ++j) {
                    uintptr_t gt = 0;
                    if (DecodeRel32Call(client.base + j, base + j, gt) && gt == getEnt) {
                        sawGetEnt = true;
                        break;
                    }
                }
                if (!sawGetEnt) {
                    continue;
                }
                // Walk back to TEST RDX,RDX prologue
                for (size_t back = 0x20; back < 0x120 && back <= i; ++back) {
                    const uint8_t* cand = client.base + i - back;
                    if (cand[0] != 0x48 || cand[1] != 0x85 || cand[2] != 0xD2) {
                        continue;
                    }
                    if (i > back) {
                        const uint8_t prev = client.base[i - back - 1];
                        if (prev != 0xCC && prev != 0x90 && prev != 0xC3 && back < 0x80) {
                            continue;
                        }
                    }
                    const uintptr_t fn = base + i - back;
                    g_origRadarIconColor = reinterpret_cast<RadarIconColorFn>(fn);
                    Log("Radar POV: RadarIconColor @ %p", reinterpret_cast<void*>(fn));
                    const auto* p = reinterpret_cast<const uint8_t*>(fn);
                    const size_t fnSize = ApproxFnSize(fn);
                    for (size_t k = 0; k + 10 < fnSize && k < 0x200; ++k) {
                        if (p[k] == 0x8B && p[k + 1] == 0x8E && p[k + 2] == 0x58 &&
                            p[k + 3] == 0x01 && p[k + 4] == 0x00 && p[k + 5] == 0x00 &&
                            p[k + 6] == 0xE8) {
                            uintptr_t resolveFn = 0;
                            if (DecodeRel32Call(p + k + 6, fn + k + 6, resolveFn) &&
                                IsInsideModule(client, resolveFn)) {
                                g_resolvePlayerByIndex =
                                    reinterpret_cast<ResolvePlayerByIndexFn>(resolveFn);
                                Log("Radar POV: ResolvePlayerByIndex @ %p",
                                    reinterpret_cast<void*>(resolveFn));
                            }
                            break;
                        }
                    }
                    break;
                }
                if (g_origRadarIconColor != nullptr) {
                    break;
                }
            }
        }
    }

    g_origRadarUpdate = reinterpret_cast<RadarUpdateFn>(radarUpdateFn);
    g_origGetLocal = reinterpret_cast<GetLocalFn>(getLocalFn);
    g_getObserverTarget = reinterpret_cast<GetObserverTargetFn>(getObsFn);
    g_getPlayerSlot =
        getPlayerSlotFn != 0 ? reinterpret_cast<GetPlayerSlotFn>(getPlayerSlotFn) : nullptr;
    g_origFindPlayerBySlot = findPlayerBySlotFn != 0
        ? reinterpret_cast<FindPlayerBySlotFn>(findPlayerBySlotFn)
        : nullptr;

    return true;
}

void ResetResolvedRadarState()
{
    g_origRadarUpdate = nullptr;
    g_origRadarDemoState = nullptr;
    g_origGetLocal = nullptr;
    g_getObserverTarget = nullptr;
    g_getPlayerSlot = nullptr;
    g_origFindPlayerBySlot = nullptr;
    g_origGetEntityBySlot = nullptr;
    g_origSetRadarIconType = nullptr;
    g_origRadarIconColor = nullptr;
    g_getCompColorArgb = nullptr;
    g_resolvePlayerByIndex = nullptr;
    g_spectatorFilterHooked = false;
    g_getEntityBySlotHooked = false;
    g_iconTypeHooked = false;
    g_iconColorHooked = false;
    g_radarDemoStateGlobalSlot = 0;
    g_radarShowAllFlagOffset = 0;
    g_installed.store(false, std::memory_order_release);
}

void DisableInstalledHooks()
{
    if (!g_minhookInitialized) {
        return;
    }
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_minhookInitialized = false;
}

void AbortInstall()
{
    DisableInstalledHooks();
    ResetResolvedRadarState();
}

bool InstallHooks()
{
    ModuleInfo client = {};
    if (!GetModuleInfo("client.dll", client)) {
        Log("Radar POV: client.dll not loaded yet");
        return false;
    }
    Log("Radar POV: client.dll @ %p size=0x%zx PE-timestamp=0x%08X", client.base, client.size,
        GetPeTimestamp(client));

    if (!ResolveRadarFunctions(client)) {
        return false;
    }

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        Log("Radar POV: MH_Initialize failed: %s (%d)", MhStatusName(st), static_cast<int>(st));
        ResetResolvedRadarState();
        return false;
    }
    g_minhookInitialized = true;

    void* updateTarget = reinterpret_cast<void*>(g_origRadarUpdate);
    void* getLocalTarget = reinterpret_cast<void*>(g_origGetLocal);
    void* findPlayerBySlotTarget = reinterpret_cast<void*>(g_origFindPlayerBySlot);
    void* demoStateTarget = nullptr;

    if (!CreateAndEnableHook(updateTarget, reinterpret_cast<void*>(&Hook_RadarUpdate),
                             reinterpret_cast<void**>(&g_origRadarUpdate), "radar_update")) {
        AbortInstall();
        return false;
    }

    if (!CreateAndEnableHook(getLocalTarget, reinterpret_cast<void*>(&Hook_GetLocal),
                             reinterpret_cast<void**>(&g_origGetLocal), "getLocal")) {
        AbortInstall();
        return false;
    }

    __try {
        void* engineState = *reinterpret_cast<void**>(g_radarDemoStateGlobalSlot);
        void** vtable = engineState != nullptr ? *reinterpret_cast<void***>(engineState) : nullptr;
        demoStateTarget = vtable != nullptr ? vtable[0x2B0 / sizeof(void*)] : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        demoStateTarget = nullptr;
    }
    if (!CreateAndEnableHook(demoStateTarget, reinterpret_cast<void*>(&Hook_RadarDemoState),
                             reinterpret_cast<void**>(&g_origRadarDemoState), "radar_demo_state")) {
        AbortInstall();
        return false;
    }

    // Essential for colours: icon path uses GetEntityBySlot(0), not getLocal.
    if (g_origGetEntityBySlot != nullptr) {
        if (CreateAndEnableHook(reinterpret_cast<void*>(g_origGetEntityBySlot),
                                reinterpret_cast<void*>(&Hook_GetEntityBySlot),
                                reinterpret_cast<void**>(&g_origGetEntityBySlot),
                                "getEntityBySlot")) {
            g_getEntityBySlotHooked = true;
        } else {
            Log("Radar POV: GetEntityBySlot hook failed");
            g_origGetEntityBySlot = nullptr;
        }
    }

    // Optional: hide freecam spectator from the player list.
    if (findPlayerBySlotTarget != nullptr && g_getPlayerSlot != nullptr) {
        if (CreateAndEnableHook(findPlayerBySlotTarget, reinterpret_cast<void*>(&Hook_FindPlayerBySlot),
                                reinterpret_cast<void**>(&g_origFindPlayerBySlot),
                                "findPlayerBySlot")) {
            g_spectatorFilterHooked = true;
        } else {
            g_origFindPlayerBySlot = reinterpret_cast<FindPlayerBySlotFn>(findPlayerBySlotTarget);
            Log("Radar POV: spectator-slot filter unavailable");
        }
    }

    // Icon type: live-teammate 0x11 → 9/0xD for native competitive RGB paint.
    if (g_origSetRadarIconType != nullptr) {
        if (CreateAndEnableHook(reinterpret_cast<void*>(g_origSetRadarIconType),
                                reinterpret_cast<void*>(&Hook_SetRadarIconType),
                                reinterpret_cast<void**>(&g_origSetRadarIconType),
                                "setRadarIconType")) {
            g_iconTypeHooked = true;
        } else {
            Log("Radar POV: SetRadarIconType hook failed");
            g_origSetRadarIconType = nullptr;
        }
    }

    // Force competitive ARGB after native icon colour update (engine palette).
    if (g_origRadarIconColor != nullptr && g_getCompColorArgb != nullptr) {
        if (CreateAndEnableHook(reinterpret_cast<void*>(g_origRadarIconColor),
                                reinterpret_cast<void*>(&Hook_RadarIconColor),
                                reinterpret_cast<void**>(&g_origRadarIconColor),
                                "radarIconColor")) {
            g_iconColorHooked = true;
        } else {
            Log("Radar POV: RadarIconColor hook failed");
        }
    } else {
        Log("Radar POV: force-color unavailable (iconColor=%p argb=%p resolve=%p)",
            reinterpret_cast<void*>(g_origRadarIconColor),
            reinterpret_cast<void*>(g_getCompColorArgb),
            reinterpret_cast<void*>(g_resolvePlayerByIndex));
    }

    g_installed.store(true, std::memory_order_release);
    Log("Radar POV: installed enabled=%d update=%d getLocal=%d getObs=%d demoState=%d "
        "getEntityBySlot=%d spectatorFilter=%d iconType=%d forceColor=%d",
        g_enabled.load() ? 1 : 0, g_origRadarUpdate != nullptr ? 1 : 0,
        g_origGetLocal != nullptr ? 1 : 0, g_getObserverTarget != nullptr ? 1 : 0,
        g_origRadarDemoState != nullptr ? 1 : 0, g_getEntityBySlotHooked ? 1 : 0,
        g_spectatorFilterHooked ? 1 : 0, g_iconTypeHooked ? 1 : 0, g_iconColorHooked ? 1 : 0);
    return true;
}

void UninstallHooks()
{
    DisableInstalledHooks();
    ResetResolvedRadarState();
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
    // Intentionally empty: do not force radar/teammate-colour cvars.
    // Upstream identity hooks alone should drive live-POV behaviour; engine
    // defaults (or the host tool's own command list) own the rest.
    (void)queueCmd;
}
