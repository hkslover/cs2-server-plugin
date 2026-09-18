#include "radar_pov.h"
#include "radar_pov/radar_resolver.h"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <cstdint>
#include <vector>
#include <Windows.h>
#include <MinHook.h>
#include "mem_utils.h"
using namespace MemUtils;
#endif

namespace {

// =============================================================================
// Design (RE-backed, validated against PE 0x6AA1AE5E): identity rewrite +
// teammate type + force ARGB.
//
// THE demo switch: engine vtable +0x2B0 = IVEngineClient::IsHLTV()
// (mov rcx,[global]; call [vtable+0x2B0]) — consumed at ~21 radar-path sites
// (radar_mode, setRadarIconType, iconColor, ...). Scoped to 0 it flips the
// whole radar into the live branch.
//
// Hooks (8):
//   radar_update, getLocal, GetEntityBySlot, demo/HLTV (IsHLTV),
//   findPlayerBySlot, IsSlotEnemyOf (restore live team gate; demo-session
//   cvar 0x182339278 reads non-zero and gates teammates into spotted-only),
//   SetRadarIconType (teammate 0x11→9/0xD + comp-allowed bit),
//   RadarIconColor (force cl_teammate_color_*)
// Colour-gate hooks removed — force-color covers them.
//
// POV activation: observer chain (getObs(local)) first; if that fails but
// getLocal() itself is a live T/CT player pawn, use it directly (newer demo
// playback exposes the POV player as the local pawn with no observer chain).
//
// PE/pattern helpers live in mem_utils.h (MemUtils) for reuse by other features.
// =============================================================================

RadarPovLogFn g_log = nullptr;
// Default off — sequence JSON "csdm_radar_pov" enables once (see main.cpp).
std::atomic<bool> g_enabled{false};
std::atomic<bool> g_installed{false};

#ifdef _WIN32
struct RadarPovFrameContext {
    int depth = 0;
    // Snapshot the feature switch once at the outermost radar update. Inner
    // detours stay on TLS and do not repeatedly touch the atomic setting.
    bool enabled = false;
    void* selfPawn = nullptr;
    bool active = false;
    int spectatorSlot = -1;
    int selfSlot = -1;
    // Observed player's m_iTeamNum (2=CT, 3=T). Competitive colours are teammates only.
    int selfTeam = 0;
};

thread_local RadarPovFrameContext g_povFrame;

inline bool IsPovFrameActive()
{
    return g_povFrame.enabled && g_povFrame.depth > 0 && g_povFrame.active;
}
#endif

std::atomic<int> g_faultRadarUpdate{0};
std::atomic<int> g_faultGetLocal{0};
std::atomic<int> g_faultResolve{0};
std::atomic<int> g_logPovOk{0};
std::atomic<int> g_logPovFail{0};
std::atomic<int> g_logPovDirect{0};
std::atomic<int> g_logSpectatorFilter{0};
std::atomic<int> g_logDemoStateOverride{0};
std::atomic<int> g_logGetEntityBySlot{0};
std::atomic<int> g_logIconType{0};
std::atomic<int> g_logIconTypeNative{0};
std::atomic<int> g_logForceColor{0};
std::atomic<int> g_logForceColorSkip{0};
std::atomic<int> g_logSlotEnemy{0};

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
// FUN_1808b0e00(localPawn, slot) — per-slot draw gate ("is this player an enemy
// of local"). Its cvar path (0x182339278 != 0 during demo playback) returns true
// for every non-self slot and hides unspotted teammates.
// MSVC x64: __fastcall is accepted but ignored (single x64 ABI), so the
// function pointer type omits it; identical to the engine-side call signature.
using IsSlotEnemyOfFn = uint8_t(*)(void* localPawn, int slot);
// FUN_180e55e00(icon, playerTeam) — writes icon type at +0x16c.
using SetRadarIconTypeFn = void(__fastcall*)(void* icon, int playerTeam);
// FUN_180e62bc0(radar, icon) — icon colour update.
using RadarIconColorFn = void(__fastcall*)(void* radar, void* icon);
// FUN_180861bb0(outArgb, colorIndex) — cl_teammate_color_N ARGB.
using GetCompColorArgbFn = uint32_t*(__fastcall*)(uint32_t* outArgb, int colorIndex);
// FUN_180a8c160(playerIndex) — resolve entity/controller for icon subject.
using ResolvePlayerByIndexFn = void*(__fastcall*)(int playerIndex);

RadarUpdateFn g_origRadarUpdate = nullptr;
RadarDemoStateFn g_origRadarDemoState = nullptr;
GetLocalFn g_origGetLocal = nullptr;
GetObserverTargetFn g_getObserverTarget = nullptr;
GetPlayerSlotFn g_getPlayerSlot = nullptr;
FindPlayerBySlotFn g_origFindPlayerBySlot = nullptr;
GetEntityBySlotFn g_origGetEntityBySlot = nullptr;
IsSlotEnemyOfFn g_origIsSlotEnemyOf = nullptr;
SetRadarIconTypeFn g_origSetRadarIconType = nullptr;
RadarIconColorFn g_origRadarIconColor = nullptr;
GetCompColorArgbFn g_getCompColorArgb = nullptr;
ResolvePlayerByIndexFn g_resolvePlayerByIndex = nullptr;

bool g_minhookInitialized = false;
bool g_minhookOwned = false;
bool g_spectatorFilterHooked = false;
bool g_getEntityBySlotHooked = false;
bool g_slotEnemyHooked = false;
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
// Engine "teammate may show competitive colours" bit (0x180e4f729, cvar==0
// same-team path). The rewrite path sets it because the engine skips it when
// the demo-session cvar reads non-zero.
constexpr ptrdiff_t kIconCompAllowedOffset = 0x17d;
constexpr uint8_t kIconCompAllowedBit = 0x8;
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

    Log("Radar POV: applied queued hook enables (%zu/8 hooks)", g_createdRadarHooks.size());
    return true;
}

bool ValidateRequiredHookTargets(const ModuleInfo& client, void* demoStateTarget)
{
    size_t resolvedHooks = 0;
    auto logTarget = [&](const char* name, uintptr_t target, const char* source,
                         size_t candidates) {
        if (IsInsideModule(client, target)) {
            Log("Radar POV: target %s @ %p RVA=0x%zx source=%s candidates=%zu", name,
                reinterpret_cast<void*>(target),
                static_cast<size_t>(target - reinterpret_cast<uintptr_t>(client.base)), source,
                candidates);
        } else {
            Log("Radar POV: target %s @ %p RVA=external source=%s candidates=%zu", name,
                reinterpret_cast<void*>(target), source, candidates);
        }
    };
    auto requireHookTarget = [&](const char* name, const void* target, bool clientCode) {
        const uintptr_t address = reinterpret_cast<uintptr_t>(target);
        const bool valid = address != 0 &&
            (clientCode ? IsInsideText(client, address) : IsExecutableAddress(address));
        if (valid) {
            ++resolvedHooks;
            logTarget(name, address, "validated", 1);
            return;
        }
        Log("Radar POV: missing required hook target: %s", name);
    };

    requireHookTarget("radar_update", reinterpret_cast<void*>(g_origRadarUpdate), true);
    requireHookTarget("getLocal", reinterpret_cast<void*>(g_origGetLocal), true);
    requireHookTarget("radar_demo_state", demoStateTarget, false);
    requireHookTarget("getEntityBySlot", reinterpret_cast<void*>(g_origGetEntityBySlot), true);
    requireHookTarget("findPlayerBySlot", reinterpret_cast<void*>(g_origFindPlayerBySlot), true);
    requireHookTarget("isSlotEnemyOf", reinterpret_cast<void*>(g_origIsSlotEnemyOf), true);
    requireHookTarget("setRadarIconType", reinterpret_cast<void*>(g_origSetRadarIconType), true);
    requireHookTarget("radarIconColor", reinterpret_cast<void*>(g_origRadarIconColor), true);

    if (resolvedHooks != 8) {
        Log("Radar POV: hook target resolution incomplete: %zu/8 hooks available", resolvedHooks);
        return false;
    }

    bool helpersResolved = true;
    auto requireHelper = [&](const char* name, const void* helper) {
        const uintptr_t address = reinterpret_cast<uintptr_t>(helper);
        if (IsInsideText(client, address)) {
            logTarget(name, address, "validated", 1);
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

    Log("Radar POV: resolved 8/8 required hook targets and helpers");
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

    if (!IsPovFrameActive()) {
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
    if (IsPovFrameActive() && g_povFrame.selfSlot >= 0 && (slot == 0 || slot == -1)) {
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
    if (realPawn == nullptr) {
        if (g_logPovFail.fetch_add(1) == 0) {
            Log("Radar POV: getLocal returned no pawn — show-all ON (fail-safe)");
        }
        return;
    }

    void* povPawn = ResolvePovSelfPawn(realPawn);
    bool directLocal = false;
    if (povPawn == nullptr) {
        // Some demo playback builds expose the recorded POV player as the
        // local pawn directly (getLocal returns the live pawn with no observer
        // chain). Fall back to the local pawn itself when it is a live player
        // pawn on team T/CT — the radar then renders that player's live
        // first-person view instead of silently degrading to show-all.
        const int localTeam = ReadEntityTeam(realPawn);
        if (IsPlayerPawn(realPawn) &&
            (localTeam == kTeamT || localTeam == kTeamCT)) {
            povPawn = realPawn;
            directLocal = true;
            if (g_logPovDirect.fetch_add(1) == 0) {
                Log("Radar POV: local pawn is the POV player (team %d) — using it directly",
                    localTeam);
            }
        }
    }
    if (povPawn == nullptr) {
        if (g_logPovFail.fetch_add(1) == 0) {
            Log("Radar POV: no observer target yet — show-all ON (fail-safe) local=%p team=%d "
                "playerPawn=%d observing=%d",
                realPawn, ReadEntityTeam(realPawn), IsPlayerPawn(realPawn) ? 1 : 0,
                LooksObserving(realPawn) ? 1 : 0);
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
        Log("Radar POV: active — pawn %p -> observed %p (slot %d team %d, spectatorSlot %d)%s",
            realPawn, povPawn, g_povFrame.selfSlot, g_povFrame.selfTeam,
            g_povFrame.spectatorSlot, directLocal ? " [direct]" : "");
    }
}

void ClearPovContext()
{
    g_povFrame.enabled = false;
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
            g_povFrame.enabled = true;
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
    // Nested updates inherit the outer frame snapshot. Only the outermost
    // update needs to read the atomic feature switch.
    const bool enabled = g_povFrame.depth > 0
        ? g_povFrame.enabled
        : g_enabled.load(std::memory_order_relaxed);
    RadarPovFrameScope frame(enabled, updateContext);
    CallOriginalRadarUpdate(updateContext, updateEnabled);
}

uint8_t __fastcall Hook_RadarDemoState(void* engineState)
{
    uint8_t result = 0;
    if (g_origRadarDemoState != nullptr) {
        result = g_origRadarDemoState(engineState);
    }
    if (IsPovFrameActive()) {
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
    if (IsPovFrameActive() && g_povFrame.spectatorSlot >= 0 &&
        slot == g_povFrame.spectatorSlot) {
        if (g_logSpectatorFilter.fetch_add(1) == 0) {
            Log("Radar POV: filtering demo spectator slot %d", g_povFrame.spectatorSlot);
        }
        return nullptr;
    }
    return g_origFindPlayerBySlot != nullptr ? g_origFindPlayerBySlot(slot) : nullptr;
}

// FUN_1808b0e00(localPawn, slot) — per-slot draw gate ("is this player an enemy
// of local"). The engine's live branch compares the slot player's team against
// the local player's team; but its team-colour cvar path (0x182339278, reads
// non-zero during demo playback) returns true for every non-self slot, which
// gates teammates behind the spotted bit and hides the unspotted ones.
// During POV frames reproduce the live branch: gate only players on a team
// different from the observed player's.
uint8_t __fastcall Hook_IsSlotEnemyOf(void* localPawn, int slot)
{
    if (IsPovFrameActive() && g_origFindPlayerBySlot != nullptr) {
        __try {
            void* player = g_origFindPlayerBySlot(slot);
            if (player != nullptr) {
                int selfTeam = g_povFrame.selfTeam;
                if (selfTeam != kTeamT && selfTeam != kTeamCT) {
                    selfTeam = RefreshPovSelfTeam();
                }
                const int playerTeam = ReadEntityTeam(player);
                if (selfTeam == kTeamT || selfTeam == kTeamCT) {
                    const int gate = (playerTeam != selfTeam) ? 1 : 0;
                    const int n = g_logSlotEnemy.fetch_add(1);
                    if (n == 0) {
                        Log("Radar POV: slot %d gate team=%d self=%d -> %d", slot,
                            playerTeam, selfTeam, gate);
                    }
                    return static_cast<uint8_t>(gate);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // fall through to the native gate
        }
    }
    return g_origIsSlotEnemyOf != nullptr ? g_origIsSlotEnemyOf(localPawn, slot) : 0;
}

// FUN_180e55e00: with live identity, same-team non-self icons become type 0x11
// when the engine's team-colour path chooses solid team panels.
// FUN_180e62bc0 live RGB only paints types 9 / 0xD. Map 0x11 → team panel type
// for POV teammates only (never rewrite enemy icons).
//
// New-build fact (radare2): the visible sub-panel is indexed by the type bit
// (per-frame updater 0xE57E20 builds visibility flags `1 << type`), so rewriting
// the type byte alone switches the rendered body to the competitive-colour panel.
void __fastcall Hook_SetRadarIconType(void* icon, int playerTeam)
{
    if (g_origSetRadarIconType != nullptr) {
        g_origSetRadarIconType(icon, playerTeam);
    }
    if (!IsPovFrameActive() || icon == nullptr) {
        return;
    }
    __try {
        auto* typePtr =
            reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(icon) + kIconTypeOffset);
        const int nativeType = *typePtr;
        const bool teammate = IsPovTeammateTeam(playerTeam);
        // Diagnostic: reveal the engine's per-icon type decision (first 12 icons).
        const int n = g_logIconTypeNative.fetch_add(1);
        if (n < 12) {
            Log("Radar POV: icon-type native=%d team=%d selfTeam=%d teammate=%d",
                nativeType, playerTeam, g_povFrame.selfTeam, teammate ? 1 : 0);
        }
        if (nativeType != kIconTypeLiveTeammate || !teammate) {
            return;
        }
        const int fixed = (playerTeam == kTeamT) ? kIconTypeT : kIconTypeCT;
        *typePtr = fixed;
        // Mirror the engine's cvar==0 teammate path: set the "competitive colours
        // allowed" bit that the players loop skips when the demo-session cvar
        // reads non-zero (0x180e4f729).
        auto* flags17d = reinterpret_cast<uint8_t*>(reinterpret_cast<uint8_t*>(icon) +
                                                    kIconCompAllowedOffset);
        *flags17d = static_cast<uint8_t>(*flags17d | kIconCompAllowedBit);
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
    if (icon == nullptr || g_getCompColorArgb == nullptr || !IsPovFrameActive()) {
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
    if (IsPovFrameActive() && icon != nullptr) {
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

    if (IsPovFrameActive()) {
        ForceCompetitiveIconColor(icon);
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

bool ResolveRadarFunctions(const ModuleInfo& client)
{
    RadarPovResolver::ResolvedState resolved = {};
    if (!RadarPovResolver::ResolveRadarFunctions(client, resolved)) {
        return false;
    }

    g_origRadarUpdate = resolved.functions.radarUpdate;
    g_origGetLocal = resolved.functions.getLocal;
    g_getObserverTarget = resolved.functions.getObserverTarget;
    g_getPlayerSlot = resolved.functions.getPlayerSlot;
    g_origFindPlayerBySlot = resolved.functions.findPlayerBySlot;
    g_origGetEntityBySlot = resolved.functions.getEntityBySlot;
    g_origIsSlotEnemyOf = resolved.functions.isSlotEnemyOf;
    g_origSetRadarIconType = resolved.functions.setRadarIconType;
    g_origRadarIconColor = resolved.functions.radarIconColor;
    g_getCompColorArgb = resolved.functions.getCompColorArgb;
    g_resolvePlayerByIndex = resolved.functions.resolvePlayerByIndex;
    g_radarDemoStateGlobalSlot = resolved.radarDemoStateGlobalSlot;
    g_radarShowAllFlagOffset = resolved.radarShowAllFlagOffset;
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
    g_origIsSlotEnemyOf = nullptr;
    g_origSetRadarIconType = nullptr;
    g_origRadarIconColor = nullptr;
    g_getCompColorArgb = nullptr;
    g_resolvePlayerByIndex = nullptr;
    g_spectatorFilterHooked = false;
    g_getEntityBySlotHooked = false;
    g_slotEnemyHooked = false;
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

    if (!ValidateRequiredHookTargets(client, demoStateTarget)) {
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
    void* isSlotEnemyOfTarget = reinterpret_cast<void*>(g_origIsSlotEnemyOf);
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

    // Required: demo-session cvar makes the native gate treat teammates as
    // enemies; restore the live team-comparison branch during POV frames.
    if (!CreateHook(isSlotEnemyOfTarget, reinterpret_cast<void*>(&Hook_IsSlotEnemyOf),
                    reinterpret_cast<void**>(&g_origIsSlotEnemyOf), "isSlotEnemyOf")) {
        Log("Radar POV: required hook failed: isSlotEnemyOf");
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
    g_slotEnemyHooked = true;
    g_iconTypeHooked = true;
    g_iconColorHooked = true;

    const int activeHooks =
        (g_origRadarUpdate != nullptr ? 1 : 0) + (g_origGetLocal != nullptr ? 1 : 0) +
        (g_origRadarDemoState != nullptr ? 1 : 0) + (g_getEntityBySlotHooked ? 1 : 0) +
        (g_spectatorFilterHooked ? 1 : 0) + (g_slotEnemyHooked ? 1 : 0) +
        (g_iconTypeHooked ? 1 : 0) + (g_iconColorHooked ? 1 : 0);
    if (activeHooks != 8 || g_createdRadarHooks.size() != 8) {
        Log("Radar POV: hook activation incomplete: %d/8 hooks active, %zu/8 targets tracked; "
            "install aborted",
            activeHooks, g_createdRadarHooks.size());
        AbortInstall();
        return false;
    }

    g_installed.store(true, std::memory_order_release);
    Log("Radar POV: installed 8/8 hooks active enabled=%d update=%d getLocal=%d getObs=%d demoState=%d "
        "getEntityBySlot=%d spectatorFilter=%d slotEnemy=%d iconType=%d forceColor=%d",
        g_enabled.load() ? 1 : 0, g_origRadarUpdate != nullptr ? 1 : 0,
        g_origGetLocal != nullptr ? 1 : 0, g_getObserverTarget != nullptr ? 1 : 0,
        g_origRadarDemoState != nullptr ? 1 : 0, g_getEntityBySlotHooked ? 1 : 0,
        g_spectatorFilterHooked ? 1 : 0, g_slotEnemyHooked ? 1 : 0, g_iconTypeHooked ? 1 : 0,
        g_iconColorHooked ? 1 : 0);
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
    RadarPovResolver::SetLogger(logger);
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
