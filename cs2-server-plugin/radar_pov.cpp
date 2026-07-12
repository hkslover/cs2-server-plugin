#include "radar_pov.h"
#include "mem_utils.h"

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
#include <MinHook.h>
using namespace MemUtils;
#endif

namespace {

// =============================================================================
// Design (Ghidra-backed): identity rewrite + teammate type + force ARGB
//
// Hooks (7):
//   radar_update, getLocal, GetEntityBySlot, demo/HLTV, findPlayerBySlot,
//   SetRadarIconType (teammate 0x11→9/0xD), RadarIconColor (force cl_teammate_color_*)
// Colour-gate hooks (863200 / 8494d0) removed — force-color covers them.
//
// PE/pattern helpers live in mem_utils.h (MemUtils) for reuse by other features.
// =============================================================================

RadarPovLogFn g_log = nullptr;
// Default off — sequence JSON "csdm_radar_pov" enables once (see main.cpp).
std::atomic<bool> g_enabled{false};
std::atomic<bool> g_installed{false};

struct RadarPovFrameContext {
    int depth = 0;
    void* selfPawn = nullptr;
    bool active = false;
    int spectatorSlot = -1;
    int selfSlot = -1;
    // Observed player's m_iTeamNum (2=CT, 3=T). Competitive colours are teammates only.
    int selfTeam = 0;
};

thread_local RadarPovFrameContext g_povFrame;

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
bool g_minhookOwned = false;
bool g_spectatorFilterHooked = false;
bool g_getEntityBySlotHooked = false;
bool g_iconTypeHooked = false;
bool g_iconColorHooked = false;
uintptr_t g_radarDemoStateGlobalSlot = 0;

struct CreatedRadarHook {
    void* target = nullptr;
    const char* name = nullptr;
};

std::vector<CreatedRadarHook> g_createdRadarHooks;

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

bool RemoveCreatedHook(const CreatedRadarHook& hook)
{
    bool removed = true;

    const MH_STATUS disableStatus = MH_DisableHook(hook.target);
    if (disableStatus != MH_OK && disableStatus != MH_ERROR_DISABLED &&
        disableStatus != MH_ERROR_NOT_CREATED) {
        Log("Radar POV: MH_DisableHook(%s) @ %p failed: %s (%d)", hook.name, hook.target,
            MhStatusName(disableStatus), static_cast<int>(disableStatus));
        removed = false;
    }

    const MH_STATUS removeStatus = MH_RemoveHook(hook.target);
    if (removeStatus != MH_OK && removeStatus != MH_ERROR_NOT_CREATED) {
        Log("Radar POV: MH_RemoveHook(%s) @ %p failed: %s (%d)", hook.name, hook.target,
            MhStatusName(removeStatus), static_cast<int>(removeStatus));
        removed = false;
    }

    if (removed) {
        Log("Radar POV: removed hook %s @ %p", hook.name, hook.target);
    }
    return removed;
}

bool RemoveCreatedHooks()
{
    if (g_createdRadarHooks.empty()) {
        return true;
    }

    std::vector<CreatedRadarHook> remaining;
    remaining.reserve(g_createdRadarHooks.size());
    for (auto it = g_createdRadarHooks.rbegin(); it != g_createdRadarHooks.rend(); ++it) {
        if (!RemoveCreatedHook(*it)) {
            remaining.push_back(*it);
        }
    }

    g_createdRadarHooks.assign(remaining.rbegin(), remaining.rend());
    if (!g_createdRadarHooks.empty()) {
        Log("Radar POV: precise hook cleanup incomplete: %zu target(s) remain",
            g_createdRadarHooks.size());
        return false;
    }
    return true;
}

void ReleaseMinHook()
{
    if (!g_minhookInitialized) {
        return;
    }

    if (!g_minhookOwned) {
        Log("Radar POV: leaving shared MinHook lifecycle initialized by another module");
        g_minhookInitialized = false;
        g_minhookOwned = false;
        return;
    }

    const MH_STATUS st = MH_Uninitialize();
    if (st != MH_OK && st != MH_ERROR_NOT_INITIALIZED) {
        Log("Radar POV: MH_Uninitialize failed: %s (%d)", MhStatusName(st),
            static_cast<int>(st));
        return;
    }

    Log("Radar POV: released MinHook lifecycle owned by Radar POV");
    g_minhookInitialized = false;
    g_minhookOwned = false;
}

bool CreateHook(void* target, void* detour, void** originalOut, const char* name)
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

    g_createdRadarHooks.push_back({target, name});

    Log("Radar POV: created hook %s @ %p (trampoline %p)", name, target, *originalOut);
    return true;
}

bool QueueHookEnable(const CreatedRadarHook& hook)
{
    const MH_STATUS st = MH_QueueEnableHook(hook.target);
    if (st != MH_OK) {
        Log("Radar POV: MH_QueueEnableHook(%s) @ %p failed: %s (%d)", hook.name, hook.target,
            MhStatusName(st), static_cast<int>(st));
        return false;
    }

    Log("Radar POV: queued hook %s @ %p for enable", hook.name, hook.target);
    return true;
}

bool ApplyQueuedHookEnables()
{
    const MH_STATUS st = MH_ApplyQueued();
    if (st != MH_OK) {
        Log("Radar POV: MH_ApplyQueued failed: %s (%d)", MhStatusName(st),
            static_cast<int>(st));
        return false;
    }

    Log("Radar POV: applied queued hook enables (%zu/7 hooks)", g_createdRadarHooks.size());
    return true;
}

bool ValidateRequiredHookTargets(void* demoStateTarget)
{
    size_t resolvedHooks = 0;
    auto requireHookTarget = [&](const char* name, const void* target) {
        if (target != nullptr) {
            ++resolvedHooks;
            return;
        }
        Log("Radar POV: missing required hook target: %s", name);
    };

    requireHookTarget("radar_update", reinterpret_cast<void*>(g_origRadarUpdate));
    requireHookTarget("getLocal", reinterpret_cast<void*>(g_origGetLocal));
    requireHookTarget("radar_demo_state", demoStateTarget);
    requireHookTarget("getEntityBySlot", reinterpret_cast<void*>(g_origGetEntityBySlot));
    requireHookTarget("findPlayerBySlot", reinterpret_cast<void*>(g_origFindPlayerBySlot));
    requireHookTarget("setRadarIconType", reinterpret_cast<void*>(g_origSetRadarIconType));
    requireHookTarget("radarIconColor", reinterpret_cast<void*>(g_origRadarIconColor));

    if (resolvedHooks != 7) {
        Log("Radar POV: hook target resolution incomplete: %zu/7 hooks available", resolvedHooks);
        return false;
    }

    bool helpersResolved = true;
    auto requireHelper = [&](const char* name, const void* helper) {
        if (helper != nullptr) {
            return;
        }
        helpersResolved = false;
        Log("Radar POV: missing required hook helper: %s", name);
    };

    requireHelper("getObs", reinterpret_cast<void*>(g_getObserverTarget));
    requireHelper("getPlayerSlot", reinterpret_cast<void*>(g_getPlayerSlot));
    requireHelper("GetCompColorArgb", reinterpret_cast<void*>(g_getCompColorArgb));
    requireHelper("ResolvePlayerByIndex", reinterpret_cast<void*>(g_resolvePlayerByIndex));

    if (!helpersResolved) {
        Log("Radar POV: required hook helper resolution incomplete; install aborted");
        return false;
    }

    Log("Radar POV: resolved 7/7 required hook targets and helpers");
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

    if (!g_enabled.load(std::memory_order_relaxed) || g_povFrame.depth <= 0 ||
        !g_povFrame.active) {
        return real;
    }
    return g_povFrame.selfPawn != nullptr ? g_povFrame.selfPawn : real;
}

// Icon colour / spectator checks use GetEntityBySlot(0), not getLocal.
// Remap demo freecam slot 0 (and -1 = local slot) to the observed player.
void* __fastcall Hook_GetEntityBySlot(int slot)
{
    if (g_origGetEntityBySlot == nullptr) {
        return nullptr;
    }
    if (g_enabled.load(std::memory_order_relaxed) && g_povFrame.depth > 0 &&
        g_povFrame.active && g_povFrame.selfSlot >= 0 && (slot == 0 || slot == -1)) {
        const int n = g_logGetEntityBySlot.fetch_add(1);
        if (n == 0) {
            Log("Radar POV: GetEntityBySlot %d -> observed slot %d", slot,
                g_povFrame.selfSlot);
        }
        return g_origGetEntityBySlot(g_povFrame.selfSlot);
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
    int team = ReadEntityTeam(g_povFrame.selfPawn);
    if (team != kTeamT && team != kTeamCT && g_origGetEntityBySlot != nullptr &&
        g_povFrame.selfSlot >= 0) {
        void* ctrl = nullptr;
        __try {
            ctrl = g_origGetEntityBySlot(g_povFrame.selfSlot);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ctrl = nullptr;
        }
        team = ReadEntityTeam(ctrl);
    }
    if (team == kTeamT || team == kTeamCT) {
        g_povFrame.selfTeam = team;
    }
    return g_povFrame.selfTeam;
}

// True only for same T/CT as the observed player (never spectators / enemies).
bool IsPovTeammateTeam(int playerTeam)
{
    if (playerTeam != kTeamT && playerTeam != kTeamCT) {
        return false;
    }
    int selfTeam = g_povFrame.selfTeam;
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
    g_povFrame.selfPawn = nullptr;
    g_povFrame.active = false;
    g_povFrame.spectatorSlot = -1;
    g_povFrame.selfSlot = -1;
    g_povFrame.selfTeam = 0;

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

    g_povFrame.selfPawn = povPawn;
    g_povFrame.active = true;
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
            g_povFrame.spectatorSlot = spectatorSlot;
        }
        if (povSlot >= 0) {
            g_povFrame.selfSlot = povSlot;
        }
    }
    RefreshPovSelfTeam();
    if (g_logPovOk.fetch_add(1) == 0) {
        Log("Radar POV: active — pawn %p -> observed %p (slot %d team %d, spectatorSlot %d)",
            realPawn, povPawn, g_povFrame.selfSlot, g_povFrame.selfTeam,
            g_povFrame.spectatorSlot);
    }
}

void ClearPovContext()
{
    g_povFrame.selfPawn = nullptr;
    g_povFrame.active = false;
    g_povFrame.spectatorSlot = -1;
    g_povFrame.selfSlot = -1;
    g_povFrame.selfTeam = 0;
}

class RadarPovFrameScope final {
public:
    RadarPovFrameScope(bool enabled, void* updateContext)
        : enabled_(enabled),
          radar_(updateContext != nullptr
                     ? reinterpret_cast<uint8_t*>(updateContext) + kRadarFromUpdateContext
                     : nullptr)
    {
        if (!enabled_) {
            return;
        }

        const bool outermost = g_povFrame.depth == 0;
        ++g_povFrame.depth;
        if (outermost) {
            PreparePovContext();
            SetShowAllFlag(radar_, !g_povFrame.active);
        }
    }

    ~RadarPovFrameScope()
    {
        if (!enabled_ || g_povFrame.depth <= 0) {
            return;
        }

        --g_povFrame.depth;
        if (g_povFrame.depth != 0) {
            return;
        }

        SetShowAllFlag(radar_, !g_povFrame.active);
        ClearPovContext();
    }

    RadarPovFrameScope(const RadarPovFrameScope&) = delete;
    RadarPovFrameScope& operator=(const RadarPovFrameScope&) = delete;

private:
    bool enabled_ = false;
    uint8_t* radar_ = nullptr;
};

void CallOriginalRadarUpdate(void* updateContext, uint8_t updateEnabled)
{
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
}

void __fastcall Hook_RadarUpdate(void* updateContext, uint8_t updateEnabled)
{
    RadarPovFrameScope frame(g_enabled.load(std::memory_order_relaxed), updateContext);
    CallOriginalRadarUpdate(updateContext, updateEnabled);
}

uint8_t __fastcall Hook_RadarDemoState(void* engineState)
{
    uint8_t result = 0;
    if (g_origRadarDemoState != nullptr) {
        result = g_origRadarDemoState(engineState);
    }
    if (g_povFrame.depth > 0 && g_povFrame.active) {
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
    if (g_enabled.load(std::memory_order_relaxed) && g_povFrame.depth > 0 &&
        g_povFrame.active && g_povFrame.spectatorSlot >= 0 &&
        slot == g_povFrame.spectatorSlot) {
        if (g_logSpectatorFilter.fetch_add(1) == 0) {
            Log("Radar POV: filtering demo spectator slot %d", g_povFrame.spectatorSlot);
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
    if (!g_enabled.load(std::memory_order_relaxed) || g_povFrame.depth <= 0 ||
        !g_povFrame.active || icon == nullptr || !IsPovTeammateTeam(playerTeam)) {
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
                playerTeam, g_povFrame.selfTeam);
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
    if (icon == nullptr || g_getCompColorArgb == nullptr || !g_povFrame.active) {
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
                type, playerTeam, g_povFrame.selfTeam, rawNetvar, colorIdx, argb, painted,
                playerIndex);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_logForceColorSkip.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in ForceCompetitiveIconColor");
        }
    }
}

void __fastcall Hook_RadarIconColor(void* radar, void* icon)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_povFrame.depth > 0 &&
        g_povFrame.active && icon != nullptr) {
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

    if (g_enabled.load(std::memory_order_relaxed) && g_povFrame.depth > 0 &&
        g_povFrame.active) {
        ForceCompetitiveIconColor(icon);
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

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

    // and byte ptr [radar+disp32], 0FEh
    if (const uint8_t* hit = FindPattern(reinterpret_cast<const uint8_t*>(radarModeFn),
                                         ApproxFnSize(radarModeFn), "80 A3 ?? ?? ?? ?? FE")) {
        g_radarShowAllFlagOffset =
            static_cast<ptrdiff_t>(*reinterpret_cast<const uint32_t*>(hit + 2));
    }
    if (g_radarShowAllFlagOffset <= 0) {
        Log("Radar POV: show-all flag offset not found");
        return false;
    }
    Log("Radar POV: show-all flag offset=0x%zx", static_cast<size_t>(g_radarShowAllFlagOffset));

    const uintptr_t radarUpdateFn = FindFunctionStart(client, modeCallSite);
    const auto* updateBytes = reinterpret_cast<const uint8_t*>(radarUpdateFn);
    // test dl,dl ... lea rsi,[rcx-20h] at +0x23
    const bool validRadarUpdate = radarUpdateFn != 0 && radarUpdateFn != radarModeFn &&
        MatchPattern(updateBytes, 0x30, "84 D2") && updateBytes[0x23] == 0x48 &&
        updateBytes[0x24] == 0x8D && updateBytes[0x25] == 0x71 && updateBytes[0x26] == 0xE0;
    if (!validRadarUpdate) {
        Log("Radar POV: full radar update wrapper shape not recognized");
        return false;
    }
    Log("Radar POV: full radar update fn @ %p size=0x%zx", reinterpret_cast<void*>(radarUpdateFn),
        ApproxFnSize(radarUpdateFn));

    // mov rcx,[rip+global]; mov rax,[rcx]; call [rax+2B0h]
    if (const uint8_t* hit =
            FindPattern(reinterpret_cast<const uint8_t*>(radarModeFn), ApproxFnSize(radarModeFn),
                        "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 B0 02 00 00")) {
        const int32_t rel = *reinterpret_cast<const int32_t*>(hit + 3);
        const size_t off = static_cast<size_t>(hit - reinterpret_cast<const uint8_t*>(radarModeFn));
        const uintptr_t slot = radarModeFn + off + 7 + static_cast<intptr_t>(rel);
        if (IsInsideModule(client, slot)) {
            g_radarDemoStateGlobalSlot = slot;
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
        // lea rdx,[rsp+24h]; mov rcx,rax; call getSlot
        const uint8_t* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
        const size_t bodySize = ApproxFnSize(radarPlayersFn);
        const size_t scan = bodySize < 0x100 ? bodySize : 0x100;
        const uint8_t* hit =
            FindPattern(body, scan, "48 8D 54 24 24 48 8B C8 E8");
        if (hit != nullptr) {
            DecodeRel32Call(hit + 8, radarPlayersFn + static_cast<size_t>(hit - body) + 8,
                            getPlayerSlotFn);
        }
    }

    {
        // mov ecx,edi; call findPlayerBySlot; mov [rsp+58h],rax; mov rbx,rax; test rax,rax
        const uint8_t* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
        const size_t bodySize = ApproxFnSize(radarPlayersFn);
        const uint8_t* hit = FindPattern(
            body, bodySize, "8B CF E8 ?? ?? ?? ?? 48 89 44 24 58 48 8B D8 48 85 C0");
        if (hit != nullptr) {
            DecodeRel32Call(hit + 2, radarPlayersFn + static_cast<size_t>(hit - body) + 2,
                            findPlayerBySlotFn);
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

    // Patterns (Afx-style hex + ??). Keep short / structural when possible.
    // GetEntityBySlot (FUN_180926920): sub rsp,28; cmp ecx,-1; ... call [rax+310h];
    // mov rax,[rcx+rax*8]; ret
    static const char kPatGetEntityBySlot[] =
        "48 83 EC 28 83 F9 FF 75 17 48 8B 0D ?? ?? ?? ?? 48 8D 54 24 30 48 8B 01 "
        "FF 90 10 03 00 00 8B 08 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8B 04 C1 48 83 C4 28 C3";
    // IsSpectatorCheck: mov [rsp+8],rbx; push rdi; sub rsp,20; mov rbx,rcx; lea; call;
    // cmp [rbx+0x3E7],1
    static const char kPatIsSpectatorCheck[] =
        "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? "
        "80 BB E7 03 00 00 01";
    // SetRadarIconType prologue ending in call getLocal
    static const char kPatSetRadarIconType[] =
        "40 56 57 41 56 48 83 EC 20 8B FA 4C 8B F1 E8";
    // GetCompColorArgb (cl_teammate_color_*)
    static const char kPatGetCompColorArgb[] =
        "40 53 48 83 EC 20 48 8B D9 83 FA FF 7D";
    // RadarIconColor (e460e0) start
    static const char kPatRadarIconColor[] =
        "48 85 D2 0F 84 ?? ?? ?? ?? 56 41 57 48 83 EC 58";

    // GetEntityBySlot: prefer call-chain from icon colour, else first body hit.
    {
        auto looksLikeGetEntityBySlot = [&](uintptr_t fn) -> bool {
            return IsInsideModule(client, fn) &&
                MatchPattern(reinterpret_cast<const uint8_t*>(fn), 0x80, kPatGetEntityBySlot);
        };

        uintptr_t isSpecFn = 0;
        if (const uint8_t* hit =
                FindPattern(client.base, client.size, kPatIsSpectatorCheck)) {
            isSpecFn = reinterpret_cast<uintptr_t>(hit);
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
            const auto hits = FindPatternAll(client.base, client.size, kPatGetEntityBySlot, 8);
            if (!hits.empty()) {
                g_origGetEntityBySlot =
                    reinterpret_cast<GetEntityBySlotFn>(reinterpret_cast<uintptr_t>(hits[0]));
                Log("Radar POV: GetEntityBySlot @ %p (pattern, %zu hits)",
                    reinterpret_cast<void*>(hits[0]), hits.size());
            }
        }

        if (g_origGetEntityBySlot == nullptr) {
            Log("Radar POV: GetEntityBySlot not found — colours may stay team-based");
        }
    }

    // FUN_180e39320 — prologue + first call is getLocal
    {
        constexpr size_t kCallGetLocalOff = 14;
        if (radarPlayersFn != 0 && getLocalFn != 0) {
            const auto* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
            const size_t bodySize = ApproxFnSize(radarPlayersFn);
            for (size_t i = 0; i + 5 < bodySize; ++i) {
                uintptr_t target = 0;
                if (!DecodeRel32Call(body + i, radarPlayersFn + i, target)) {
                    continue;
                }
                if (!IsInsideModule(client, target) ||
                    !MatchPattern(reinterpret_cast<const uint8_t*>(target), 0x20,
                                  kPatSetRadarIconType)) {
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
            // Fallback: unique prologue scan (verify first call == getLocal when known).
            if (const uint8_t* hit =
                    FindPattern(client.base, client.size, kPatSetRadarIconType)) {
                const uintptr_t fn = reinterpret_cast<uintptr_t>(hit);
                uintptr_t first = 0;
                if (getLocalFn == 0 ||
                    (DecodeRel32Call(hit + kCallGetLocalOff, fn + kCallGetLocalOff, first) &&
                     first == getLocalFn)) {
                    g_origSetRadarIconType = reinterpret_cast<SetRadarIconTypeFn>(fn);
                    Log("Radar POV: SetRadarIconType @ %p (pattern)", reinterpret_cast<void*>(fn));
                }
            }
        }
        if (g_origSetRadarIconType == nullptr) {
            Log("Radar POV: SetRadarIconType not found — live type 0x11 may block RGB");
        }
    }

    if (const uint8_t* hit = FindPattern(client.base, client.size, kPatGetCompColorArgb)) {
        g_getCompColorArgb =
            reinterpret_cast<GetCompColorArgbFn>(reinterpret_cast<uintptr_t>(hit));
        Log("Radar POV: GetCompColorArgb @ %p", hit);
    }

    // FUN_180e460e0: pattern prologue, then extract ResolvePlayerByIndex call.
    if (const uint8_t* hit = FindPattern(client.base, client.size, kPatRadarIconColor)) {
        const uintptr_t fn = reinterpret_cast<uintptr_t>(hit);
        g_origRadarIconColor = reinterpret_cast<RadarIconColorFn>(fn);
        Log("Radar POV: RadarIconColor @ %p", reinterpret_cast<void*>(fn));
        const auto* p = hit;
        const size_t fnSize = ApproxFnSize(fn);
        // mov ecx,[rsi+0x158]; call ResolvePlayerByIndex
        if (const uint8_t* callSite =
                FindPattern(p, fnSize < 0x200 ? fnSize : 0x200, "8B 8E 58 01 00 00 E8")) {
            uintptr_t resolveFn = 0;
            if (DecodeRel32Call(callSite + 6,
                                fn + static_cast<size_t>(callSite - p) + 6, resolveFn) &&
                IsInsideModule(client, resolveFn)) {
                g_resolvePlayerByIndex = reinterpret_cast<ResolvePlayerByIndexFn>(resolveFn);
                Log("Radar POV: ResolvePlayerByIndex @ %p", reinterpret_cast<void*>(resolveFn));
            }
        }
    } else {
        Log("Radar POV: RadarIconColor not found");
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

void AbortInstall()
{
    const bool hooksRemoved = RemoveCreatedHooks();
    if (hooksRemoved) {
        ReleaseMinHook();
    } else {
        Log("Radar POV: install rollback left %zu target(s) tracked for retry",
            g_createdRadarHooks.size());
    }
    ResetResolvedRadarState();
}

bool InstallHooks()
{
    if (!g_createdRadarHooks.empty()) {
        Log("Radar POV: cleaning up %zu target(s) left by a previous failed install",
            g_createdRadarHooks.size());
        if (!RemoveCreatedHooks()) {
            Log("Radar POV: previous install cleanup still incomplete; refusing reinstall");
            return false;
        }
        ReleaseMinHook();
    }

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

    void* demoStateTarget = nullptr;
    __try {
        void* engineState = *reinterpret_cast<void**>(g_radarDemoStateGlobalSlot);
        void** vtable = engineState != nullptr ? *reinterpret_cast<void***>(engineState) : nullptr;
        demoStateTarget = vtable != nullptr ? vtable[0x2B0 / sizeof(void*)] : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        demoStateTarget = nullptr;
    }

    if (!ValidateRequiredHookTargets(demoStateTarget)) {
        ResetResolvedRadarState();
        return false;
    }

    if (!g_minhookInitialized) {
        MH_STATUS st = MH_Initialize();
        if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
            Log("Radar POV: MH_Initialize failed: %s (%d)", MhStatusName(st),
                static_cast<int>(st));
            ResetResolvedRadarState();
            return false;
        }
        g_minhookInitialized = true;
        g_minhookOwned = st == MH_OK;
        Log("Radar POV: MinHook lifecycle ready owned=%d (%s)", g_minhookOwned ? 1 : 0,
            MhStatusName(st));
    } else {
        Log("Radar POV: reusing MinHook lifecycle owned=%d", g_minhookOwned ? 1 : 0);
    }

    void* updateTarget = reinterpret_cast<void*>(g_origRadarUpdate);
    void* getLocalTarget = reinterpret_cast<void*>(g_origGetLocal);
    void* demoStateTargetForHook = demoStateTarget;
    void* getEntityBySlotTarget = reinterpret_cast<void*>(g_origGetEntityBySlot);
    void* findPlayerBySlotTarget = reinterpret_cast<void*>(g_origFindPlayerBySlot);
    void* setRadarIconTypeTarget = reinterpret_cast<void*>(g_origSetRadarIconType);
    void* radarIconColorTarget = reinterpret_cast<void*>(g_origRadarIconColor);

    // Stage 3: create all hooks before changing any target's executable bytes.
    if (!CreateHook(updateTarget, reinterpret_cast<void*>(&Hook_RadarUpdate),
                    reinterpret_cast<void**>(&g_origRadarUpdate), "radar_update")) {
        AbortInstall();
        return false;
    }

    if (!CreateHook(getLocalTarget, reinterpret_cast<void*>(&Hook_GetLocal),
                    reinterpret_cast<void**>(&g_origGetLocal), "getLocal")) {
        AbortInstall();
        return false;
    }

    if (!CreateHook(demoStateTargetForHook, reinterpret_cast<void*>(&Hook_RadarDemoState),
                    reinterpret_cast<void**>(&g_origRadarDemoState), "radar_demo_state")) {
        AbortInstall();
        return false;
    }

    // Essential for colours: icon path uses GetEntityBySlot(0), not getLocal.
    if (!CreateHook(getEntityBySlotTarget, reinterpret_cast<void*>(&Hook_GetEntityBySlot),
                    reinterpret_cast<void**>(&g_origGetEntityBySlot), "getEntityBySlot")) {
        Log("Radar POV: required hook failed: getEntityBySlot");
        AbortInstall();
        return false;
    }

    // Required: hide freecam spectator from the player list.
    if (!CreateHook(findPlayerBySlotTarget, reinterpret_cast<void*>(&Hook_FindPlayerBySlot),
                    reinterpret_cast<void**>(&g_origFindPlayerBySlot), "findPlayerBySlot")) {
        Log("Radar POV: required hook failed: findPlayerBySlot");
        AbortInstall();
        return false;
    }

    // Icon type: live-teammate 0x11 → 9/0xD for native competitive RGB paint.
    if (!CreateHook(setRadarIconTypeTarget, reinterpret_cast<void*>(&Hook_SetRadarIconType),
                    reinterpret_cast<void**>(&g_origSetRadarIconType), "setRadarIconType")) {
        Log("Radar POV: required hook failed: setRadarIconType");
        AbortInstall();
        return false;
    }

    // Force competitive ARGB after native icon colour update (engine palette).
    if (!CreateHook(radarIconColorTarget, reinterpret_cast<void*>(&Hook_RadarIconColor),
                    reinterpret_cast<void**>(&g_origRadarIconColor), "radarIconColor")) {
        Log("Radar POV: required hook failed: radarIconColor");
        AbortInstall();
        return false;
    }

    // Queue all enables only after every hook has been created. This keeps the
    // target set inactive until one final MH_ApplyQueued call below.
    for (const CreatedRadarHook& hook : g_createdRadarHooks) {
        if (!QueueHookEnable(hook)) {
            AbortInstall();
            return false;
        }
    }

    if (!ApplyQueuedHookEnables()) {
        AbortInstall();
        return false;
    }

    g_getEntityBySlotHooked = true;
    g_spectatorFilterHooked = true;
    g_iconTypeHooked = true;
    g_iconColorHooked = true;

    const int activeHooks =
        (g_origRadarUpdate != nullptr ? 1 : 0) + (g_origGetLocal != nullptr ? 1 : 0) +
        (g_origRadarDemoState != nullptr ? 1 : 0) + (g_getEntityBySlotHooked ? 1 : 0) +
        (g_spectatorFilterHooked ? 1 : 0) + (g_iconTypeHooked ? 1 : 0) +
        (g_iconColorHooked ? 1 : 0);
    if (activeHooks != 7 || g_createdRadarHooks.size() != 7) {
        Log("Radar POV: hook activation incomplete: %d/7 hooks active, %zu/7 targets tracked; "
            "install aborted",
            activeHooks, g_createdRadarHooks.size());
        AbortInstall();
        return false;
    }

    g_installed.store(true, std::memory_order_release);
    Log("Radar POV: installed 7/7 hooks active enabled=%d update=%d getLocal=%d getObs=%d demoState=%d "
        "getEntityBySlot=%d spectatorFilter=%d iconType=%d forceColor=%d",
        g_enabled.load() ? 1 : 0, g_origRadarUpdate != nullptr ? 1 : 0,
        g_origGetLocal != nullptr ? 1 : 0, g_getObserverTarget != nullptr ? 1 : 0,
        g_origRadarDemoState != nullptr ? 1 : 0, g_getEntityBySlotHooked ? 1 : 0,
        g_spectatorFilterHooked ? 1 : 0, g_iconTypeHooked ? 1 : 0, g_iconColorHooked ? 1 : 0);
    return true;
}

void UninstallHooks()
{
    if (!RemoveCreatedHooks()) {
        Log("Radar POV: uninstall incomplete; %zu target(s) remain tracked",
            g_createdRadarHooks.size());
        return;
    }
    ReleaseMinHook();
    ResetResolvedRadarState();
    Log("Radar POV: MinHook hooks removed precisely");
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
