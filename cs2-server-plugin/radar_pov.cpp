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

RadarPovLogFn g_log = nullptr;
std::atomic<bool> g_enabled{true};
std::atomic<bool> g_installed{false};

// Redirect getLocal for the complete CCSGO_HudRadar update. Player icons alone
// are not enough: radar_mode runs first and chooses the spectator vs. live-POV
// layout (rotation, player palette, sound pings and death states).
thread_local int g_inRadarUpdate = 0;
// Observer-target *pawn* used as self for this radar tick (same type as getLocal).
thread_local void* g_povSelfPawn = nullptr;
thread_local bool g_povActive = false;
// Demo owns a separate spectator pawn / player slot. It is not part of a live
// player's radar world and must not be allowed through the normal slot loop.
thread_local int g_spectatorSlot = -1;
// Observed player's controller slot (for FUN_180926920 local remapping).
thread_local int g_povSelfSlot = -1;

std::atomic<int> g_faultRadarUpdate{0};
std::atomic<int> g_faultGetLocal{0};
std::atomic<int> g_faultResolve{0};
std::atomic<int> g_logPovOk{0};
std::atomic<int> g_logPovFail{0};
std::atomic<int> g_logSpectatorFilter{0};
std::atomic<int> g_logPresentationOverride{0};
std::atomic<int> g_logDemoStateOverride{0};
std::atomic<int> g_logIsSpecCheckCalls{0};
std::atomic<int> g_logGetEntityBySlot{0};
std::atomic<int> g_logIconTypeFix{0};
std::atomic<int> g_logCompColorApply{0};
std::atomic<int> g_logCompColorSkip{0};

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
    // Some short radar update wrappers begin with `test dl,dl` before saving
    // registers; accept it only when preceded by a function boundary.
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
// Hooks
// ---------------------------------------------------------------------------

using RadarUpdateFn = void(__fastcall*)(void* updateContext, uint8_t updateEnabled);
// Selects the radar's live-POV (1) versus spectator (0) Panorama panel set.
using RadarPresentationFn = void(__fastcall*)(void* radar, uint8_t localPov, uint8_t force);
// Engine-side demo / HLTV state queried by radar_mode and player icon classes.
using RadarDemoStateFn = uint8_t(__fastcall*)(void* engineState);
using GetLocalFn = void*(__fastcall*)();
// getObs(localPawn) — first insn is mov rcx,[rcx+0x1220] (observer services on pawn).
using GetObserverTargetFn = void*(__fastcall*)(void* localPawn);
// Writes the pawn's player slot to outSlot (the radar function calls it right
// after getLocal).
using GetPlayerSlotFn = void(__fastcall*)(void* pawn, int* outSlot);
// Resolves the player entity used by the per-slot radar loop.
using FindPlayerBySlotFn = void*(__fastcall*)(int slot);
// Per-player icon renderer checks FUN_18085b540 (entity->m_iTeamNum == 1 etc.) in
// addition to the vtable+0x2B0 demo state.  It must return false during a POV frame
// or the engine keeps the spectator team-colour path instead of per-player colours.
using IsSpectatorCheckFn = uint8_t(__fastcall*)(void* entity);
// Controller lookup by player slot: FUN_180926920.  Icon colour path calls this
// with slot 0 (hardcoded) as "local" — in demos that is the spectator controller.
using GetEntityBySlotFn = void*(__fastcall*)(int slot);
// FUN_180e39320(icon, playerTeam): selects radar icon panel type (stored at +0x16c).
using SetRadarIconTypeFn = void(__fastcall*)(void* icon, int playerTeam);
// FUN_180e460e0(radar, icon): per-player icon colour / class update.
using RadarIconColorFn = void(__fastcall*)(void* radar, void* icon);
// FUN_180863200(localTeam, iconTeam): gate for competitive colour paint.
using ShouldApplyCompColorFn = uint8_t(__fastcall*)(int localTeam, int iconTeam);
// FUN_1808494d0(controller): m_iCompTeammateColor or -1 when gated off.
using GetCompTeammateColorFn = int(__fastcall*)(void* controller);
// FUN_180849370(outArgb, colorIndex): fills cl_teammate_color_N ARGB.
using GetCompColorArgbFn = uint32_t*(__fastcall*)(uint32_t* outArgb, int colorIndex);
// FUN_180a732c0(playerIndex): controller (or related) for radar icon subject.
using ResolvePlayerByIndexFn = void*(__fastcall*)(int playerIndex);

RadarUpdateFn g_origRadarUpdate = nullptr;
RadarPresentationFn g_origRadarPresentation = nullptr;
RadarDemoStateFn g_origRadarDemoState = nullptr;
GetLocalFn g_origGetLocal = nullptr;
GetObserverTargetFn g_getObserverTarget = nullptr;
GetPlayerSlotFn g_getPlayerSlot = nullptr;
FindPlayerBySlotFn g_origFindPlayerBySlot = nullptr;
IsSpectatorCheckFn g_origIsSpectatorCheck = nullptr;
GetEntityBySlotFn g_origGetEntityBySlot = nullptr;
SetRadarIconTypeFn g_origSetRadarIconType = nullptr;
RadarIconColorFn g_origRadarIconColor = nullptr;
ShouldApplyCompColorFn g_origShouldApplyCompColor = nullptr;
GetCompTeammateColorFn g_origGetCompTeammateColor = nullptr;
GetCompColorArgbFn g_getCompColorArgb = nullptr;
ResolvePlayerByIndexFn g_resolvePlayerByIndex = nullptr;

bool g_minhookInitialized = false;
bool g_spectatorFilterHooked = false;
bool g_getEntityBySlotHooked = false;
bool g_iconTypeHooked = false;
bool g_iconColorHooked = false;
bool g_compColorGateHooked = false;
uintptr_t g_radarDemoStateGlobalSlot = 0;

// Icon type field written by FUN_180e39320 / read by FUN_180e460e0 colour paint.
constexpr ptrdiff_t kIconTypeOffset = 0x16c;
// Player index used by FUN_180a732c0 / team-counter lookup.
constexpr ptrdiff_t kIconPlayerIndexOffset = 0x158;
// Rate-limit timestamp; set old to force a colour refresh each POV frame.
constexpr ptrdiff_t kIconColorTimeOffset = 0x14c;
// m_iTeamNum on controller (byte).
constexpr ptrdiff_t kControllerTeamOffset = 0x3E7;
// m_iCompTeammateColor on CCSPlayerController.
constexpr ptrdiff_t kCompTeammateColorOffset = 0x850;
// Live-FOG teammate icon type (no competitive RGB paint in e460e0).
constexpr int kIconTypeLiveTeammate = 0x11;
// Spectator-style types that e460e0 live RGB path actually paints.
constexpr int kIconTypeTerrorist = 9;
constexpr int kIconTypeCT = 0xd;
constexpr int kTeamT = 3;
constexpr int kTeamCT = 2;
// Panels that e460e0 paints with competitive ARGB (T set then CT set).
constexpr ptrdiff_t kCompColorPanelOffs[] = {0x60, 0x68, 0x70, 0x80, 0x88, 0x90};
// Panorama style vtable: +0x230 get style-ish, +0x188 set color.
constexpr size_t kPanelGetStyleVtableByteOff = 0x230;
constexpr size_t kStyleSetColorVtableByteOff = 0x188;

// getLocal validates return with vtable+0x4D8 = IsPlayerPawn (index 155).
constexpr size_t kIsPlayerPawnVtableByteOff = 0x4D8;
// players / mode: call [vtable+0xAA0] before getObs.
constexpr size_t kIsObserverVtableByteOff = 0xAA0;
// Observer services pointer on pawn (getObs first load).
constexpr ptrdiff_t kPawnObserverServices = 0x1220;
// Current radar update wrapper derives CCSGO_HudRadar as `lea rsi,[rcx-20h]`.
constexpr ptrdiff_t kRadarFromUpdateContext = -0x20;
// Resolved from radar_mode's `and byte ptr [radar+offset], ~1` instruction.
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
    if (g_povSelfPawn != nullptr) {
        return g_povSelfPawn;
    }
    return real;
}

// Resolve the observed pawn once before the outer radar update. All radar
// sub-systems then obtain the same pawn through Hook_GetLocal.
void PreparePovContext()
{
    g_povSelfPawn = nullptr;
    g_povActive = false;
    g_spectatorSlot = -1;
    g_povSelfSlot = -1;

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
    if (g_logPovOk.fetch_add(1) == 0) {
        Log("Radar POV: active — self pawn %p -> observed pawn %p (slot %d, spectatorSlot %d)",
            realPawn, povPawn, g_povSelfSlot, g_spectatorSlot);
    }
}

void ClearPovContext()
{
    g_povSelfPawn = nullptr;
    g_povActive = false;
    g_spectatorSlot = -1;
    g_povSelfSlot = -1;
}

// Parent update contains radar_mode, player icons and RadarPlayerSoundSnippet.
// Keeping the redirect alive for this full call makes all three consume the
// target pawn, matching the live first-person branch rather than only its FOG.
void __fastcall Hook_RadarUpdate(void* updateContext, uint8_t updateEnabled)
{
    const bool wantPov = g_enabled.load(std::memory_order_relaxed);
    auto* radar = reinterpret_cast<uint8_t*>(updateContext) + kRadarFromUpdateContext;
    if (wantPov) {
        ++g_inRadarUpdate;
        PreparePovContext();
        // Preserve the historical fail-safe: no observer target means normal
        // demo show-all rather than an empty radar.
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
        // radar_mode can rewrite this during the frame; enforce the final
        // first-person/fail-safe result once native rendering is complete.
        SetShowAllFlag(radar, !g_povActive);
        if (g_inRadarUpdate > 0) {
            --g_inRadarUpdate;
        }
        ClearPovContext();
    }
}

// radar_mode combines getLocal with independent demo / HLTV conditions before
// it reaches this selector. Those conditions otherwise keep the spectator
// Panorama panels active even when getLocal has been redirected. The live-POV
// panel set is the engine's native rotating, local-player presentation.
void __fastcall Hook_RadarPresentation(void* radar, uint8_t localPov, uint8_t force)
{
    if (g_inRadarUpdate > 0 && g_povActive) {
        if (g_logPresentationOverride.fetch_add(1) == 0) {
            Log("Radar POV: native live-POV radar presentation selector %u -> 1",
                static_cast<unsigned>(localPov));
        }
        localPov = 1;
    }
    if (g_origRadarPresentation != nullptr) {
        g_origRadarPresentation(radar, localPov, force);
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
            Log("Radar POV: native demo/HLTV state %u -> 0 for radar frame",
                static_cast<unsigned>(result));
        }
        return 0;
    }
    return result;
}

// Make the demo-only spectator slot look absent to the radar's normal player
// enumeration. This preserves the engine's own spotted and color paths for
// every actual player, rather than trying to synthesize an icon state.
void* __fastcall Hook_FindPlayerBySlot(int slot)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        slot == g_spectatorSlot) {
        if (g_logSpectatorFilter.fetch_add(1) == 0) {
            Log("Radar POV: filtering demo spectator slot %d from player icons", slot);
        }
        return nullptr;
    }
    return g_origFindPlayerBySlot != nullptr ? g_origFindPlayerBySlot(slot) : nullptr;
}

// FUN_18085b540(entity): returns 1 if the entity is a spectator (m_iTeamNum == 1
// or 0x788/0x6E8 flags).  The per-player icon renderer calls it alongside the
// engine demo-state check; both must return false for the engine to select the
// live per-player colour classes rather than team-colour classes.
//
// Note: the icon renderer obtains "local" via FUN_180926920(0) (slot 0 / demo
// spectator controller), NOT getLocal.  So Hook_GetLocal alone never steers this
// check — we must force false while a POV radar frame is active.
uint8_t __fastcall Hook_IsSpectatorCheck(void* entity)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive) {
        const int n = g_logIsSpecCheckCalls.fetch_add(1);
        if (n == 0 || n == 50 || n == 500) {
            Log("Radar POV: IsSpectatorCheck forced 0 (call #%d, entity=%p)", n + 1, entity);
        }
        return 0;
    }
    return g_origIsSpectatorCheck != nullptr ? g_origIsSpectatorCheck(entity) : 0;
}

// FUN_180926920(slot): returns the controller at the global player-slot array.
// Icon colour code (FUN_180e460e0) hardcodes slot 0 as "local".  In demos that is
// the freecam spectator (team 1).  Live colour paint then requires:
//   FUN_180848f80(local) == 2 (CT) or 3 (T)
// so a spectator local skips all competitive RGB application even when the
// spectator-vs-live branch is forced open.  Remap 0 / -1 to the observed slot.
void* __fastcall Hook_GetEntityBySlot(int slot)
{
    if (g_origGetEntityBySlot == nullptr) {
        return nullptr;
    }
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        g_povSelfSlot >= 0 && (slot == 0 || slot == -1)) {
        const int n = g_logGetEntityBySlot.fetch_add(1);
        if (n == 0 || n == 50) {
            Log("Radar POV: GetEntityBySlot %d -> observed slot %d", slot, g_povSelfSlot);
        }
        return g_origGetEntityBySlot(g_povSelfSlot);
    }
    return g_origGetEntityBySlot(slot);
}

// FUN_180e39320 picks the icon panel type:
//   spectator / demo  → 9 (T) or 0xD (CT)  — competitive RGB paint works
//   live teammate     → 0x11               — e460e0 skips RGB (team-coloured panels)
// Forcing live (IsSpectatorCheck=0, demo=0) therefore yields type 0x11 and team colours
// even after the colour gate is open.  Map 0x11 back to 9/0xD so the engine's own
// live competitive colour path in FUN_180e460e0 runs for teammates.
void __fastcall Hook_SetRadarIconType(void* icon, int playerTeam)
{
    if (g_origSetRadarIconType != nullptr) {
        g_origSetRadarIconType(icon, playerTeam);
    }
    if (!g_enabled.load(std::memory_order_relaxed) || g_inRadarUpdate <= 0 || !g_povActive ||
        icon == nullptr) {
        return;
    }
    __try {
        auto* typePtr = reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(icon) + kIconTypeOffset);
        const int type = *typePtr;
        if (type != kIconTypeLiveTeammate) {
            return;
        }
        int fixed = type;
        if (playerTeam == kTeamT) {
            fixed = kIconTypeTerrorist;
        } else if (playerTeam == kTeamCT) {
            fixed = kIconTypeCT;
        } else {
            return;
        }
        *typePtr = fixed;
        const int n = g_logIconTypeFix.fetch_add(1);
        if (n == 0 || n == 20) {
            Log("Radar POV: icon type 0x11 -> %d (team %d) for competitive RGB paint", fixed,
                playerTeam);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // ignore
    }
}

// FUN_180863200: engine refuses competitive colours when max-players gate /
// game-rules / mode checks fail.  During POV, allow paint for T/CT icon teams.
uint8_t __fastcall Hook_ShouldApplyCompColor(int localTeam, int iconTeam)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        (iconTeam == kTeamT || iconTeam == kTeamCT)) {
        return 1;
    }
    return g_origShouldApplyCompColor != nullptr ? g_origShouldApplyCompColor(localTeam, iconTeam)
                                                 : 0;
}

// FUN_1808494d0: bypass game-rules / mode gate; return m_iCompTeammateColor.
int __fastcall Hook_GetCompTeammateColor(void* controller)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        controller != nullptr) {
        __try {
            const int c =
                *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(controller) +
                                        kCompTeammateColorOffset);
            if (c >= 0 && c <= 4) {
                return c;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // fall through
        }
    }
    return g_origGetCompTeammateColor != nullptr ? g_origGetCompTeammateColor(controller) : -1;
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
        void** vtable = *reinterpret_cast<void***>(inner);
        if (vtable == nullptr) {
            return false;
        }
        using GetStyleFn = void*(__fastcall*)(void*);
        auto getStyle =
            reinterpret_cast<GetStyleFn>(vtable[kPanelGetStyleVtableByteOff / sizeof(void*)]);
        if (getStyle == nullptr) {
            return false;
        }
        void* style = getStyle(inner);
        if (style == nullptr) {
            return false;
        }
        void** styleVt = *reinterpret_cast<void***>(style);
        if (styleVt == nullptr) {
            return false;
        }
        using SetColorFn = void(__fastcall*)(void*, uint32_t*);
        auto setColor =
            reinterpret_cast<SetColorFn>(styleVt[kStyleSetColorVtableByteOff / sizeof(void*)]);
        if (setColor == nullptr) {
            return false;
        }
        setColor(style, argb);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Force-apply cl_teammate_color_* ARGB onto the same panels the engine paints in
// FUN_180e460e0.  Used after the native call so rate-limit / mode gates cannot
// leave teammates on solid team orange/blue.
void ForceApplyCompColors(void* icon)
{
    if (icon == nullptr || g_getCompColorArgb == nullptr || !g_povActive) {
        return;
    }

    void* controller = nullptr;
    int playerIndex = -1;
    int colorIdx = -1;
    int playerTeam = 0;
    int localTeam = 0;

    __try {
        playerIndex =
            *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(icon) + kIconPlayerIndexOffset);
        if (g_resolvePlayerByIndex != nullptr && playerIndex != -1) {
            controller = g_resolvePlayerByIndex(playerIndex);
        }
        if (controller == nullptr) {
            const int n = g_logCompColorSkip.fetch_add(1);
            if (n == 0) {
                Log("Radar POV: comp-colour skip — no controller for playerIndex=%d", playerIndex);
            }
            return;
        }

        playerTeam = static_cast<unsigned char>(
            *(reinterpret_cast<uint8_t*>(controller) + kControllerTeamOffset));
        if (playerTeam != kTeamT && playerTeam != kTeamCT) {
            return;
        }

        // Only recolour teammates of the observed player (enemies stay native).
        if (g_origGetEntityBySlot != nullptr && g_povSelfSlot >= 0) {
            void* localCtrl = g_origGetEntityBySlot(g_povSelfSlot);
            if (localCtrl != nullptr) {
                localTeam = static_cast<unsigned char>(
                    *(reinterpret_cast<uint8_t*>(localCtrl) + kControllerTeamOffset));
                if ((localTeam == kTeamT || localTeam == kTeamCT) && playerTeam != localTeam) {
                    return;
                }
            }
        }

        colorIdx = *reinterpret_cast<int*>(reinterpret_cast<uint8_t*>(controller) +
                                           kCompTeammateColorOffset);
        if (colorIdx < 0 || colorIdx > 4) {
            // Demo entities sometimes leave the netvar unset; fall back to a
            // stable per-player bucket so icons are still distinct.
            colorIdx = playerIndex >= 0 ? (playerIndex % 5) : 0;
        }

        uint32_t argb = 0;
        g_getCompColorArgb(&argb, colorIdx);
        if (argb == 0) {
            return;
        }

        int painted = 0;
        for (ptrdiff_t off : kCompColorPanelOffs) {
            if (SetIconPanelColor(icon, off, &argb)) {
                ++painted;
            }
        }

        const int n = g_logCompColorApply.fetch_add(1);
        if (n == 0 || n == 25) {
            Log("Radar POV: comp-colour apply idx=%d argb=0x%08X team=%d localTeam=%d panels=%d "
                "playerIndex=%d",
                colorIdx, argb, playerTeam, localTeam, painted, playerIndex);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (g_logCompColorSkip.fetch_add(1) == 0) {
            Log("Radar POV: EXCEPTION in ForceApplyCompColors");
        }
    }
}

// FUN_180e460e0: force a colour refresh every POV frame, then ensure competitive
// ARGB is written even when native gates no-op.
void __fastcall Hook_RadarIconColor(void* radar, void* icon)
{
    if (g_enabled.load(std::memory_order_relaxed) && g_inRadarUpdate > 0 && g_povActive &&
        icon != nullptr) {
        __try {
            // Native live path rate-limits on this float; keep it stale so paint runs.
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
        ForceApplyCompColors(icon);
    }
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

    // The first operation in radar_mode clears its show-all bit:
    // `and byte ptr [radar+offset], ~1`. Resolve the offset rather than
    // assuming it remains 0x17760 after a client update.
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

    // The direct caller runs radar_mode, player updates and sound snippets as
    // one HUD frame. Validate its current wrapper shape before relying on the
    // `lea rsi,[rcx-20h]` conversion to CCSGO_HudRadar.
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

    // The final mode call selects the panel set. Verify the callee's current
    // prologue and its radar+0x60 state byte before hooking it.
    uintptr_t radarPresentationFn = 0;
    const auto modeCalls = CollectDirectCalls(radarModeFn, ApproxFnSize(radarModeFn));
    for (uintptr_t candidate : modeCalls) {
        if (!IsInsideModule(client, candidate)) {
            continue;
        }
        const uint8_t* b = reinterpret_cast<const uint8_t*>(candidate);
        if (b[0] == 0x40 && b[1] == 0x53 && b[2] == 0x48 && b[3] == 0x83 && b[4] == 0xEC &&
            b[5] == 0x20 && b[6] == 0x83 && b[7] == 0xB9 && b[8] == 0x70 && b[9] == 0x01 &&
            b[10] == 0x00 && b[11] == 0x00 && b[12] == 0xFF) {
            radarPresentationFn = candidate;
            break;
        }
    }
    if (radarPresentationFn == 0) {
        Log("Radar POV: native radar presentation selector not found");
        return false;
    }
    Log("Radar POV: native radar presentation selector @ %p", reinterpret_cast<void*>(radarPresentationFn));

    // radar_mode and per-player class selection both call the same engine
    // demo/HLTV virtual predicate: mov rcx,[rip+global]; mov rax,[rcx];
    // call [rax+2B0h]. It must be false inside a simulated live-POV radar
    // frame or native rendering keeps the spectator color classes.
    for (size_t i = 0; i + 15 < ApproxFnSize(radarModeFn); ++i) {
        const uint8_t* b = reinterpret_cast<const uint8_t*>(radarModeFn + i);
        if (b[0] != 0x48 || b[1] != 0x8B || b[2] != 0x0D || b[7] != 0x48 ||
            b[8] != 0x8B || b[9] != 0x01 || b[10] != 0xFF || b[11] != 0x90 ||
            b[12] != 0xB0 || b[13] != 0x02 || b[14] != 0x00 || b[15] != 0x00) {
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
    Log("Radar POV: native demo/HLTV state global @ %p",
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
    uintptr_t getPlayerSlotFn = 0;
    uintptr_t findPlayerBySlotFn = 0;
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

    // getSlot is immediately after getLocal:
    //   lea rdx,[rsp+24h]; mov rcx,rax; call getSlot
    // Do not use a fixed call index: the surrounding helper list changes more
    // often than this small call-site shape.
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

    // Per-slot loop:
    //   mov ecx,edi; call findPlayerBySlot; mov [rsp+58h],rax; mov rbx,rax; test rax,rax
    // This is the narrowest safe interception point for excluding the extra
    // demo spectator slot before it can create a radar icon.
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

    // Sanity: getLocal should be small and contain call to IsPlayerPawn path.
    if (getLocalFn != 0) {
        Log("Radar POV: helpers getLocal=%p size=0x%zx getSlot=%p getObs=%p size=0x%zx "
            "findPlayerBySlot=%p",
            reinterpret_cast<void*>(getLocalFn), ApproxFnSize(getLocalFn),
            reinterpret_cast<void*>(getPlayerSlotFn), reinterpret_cast<void*>(getObsFn),
            getObsFn ? ApproxFnSize(getObsFn) : 0, reinterpret_cast<void*>(findPlayerBySlotFn));
    }

    if (getLocalFn == 0 || getObsFn == 0) {
        Log("Radar POV: helpers incomplete (getLocal=%p getObs=%p)",
            reinterpret_cast<void*>(getLocalFn), reinterpret_cast<void*>(getObsFn));
        // InstallHooks will decline the feature rather than half-applying it.
    }

    g_origRadarUpdate = reinterpret_cast<RadarUpdateFn>(radarUpdateFn);
    g_origRadarPresentation = reinterpret_cast<RadarPresentationFn>(radarPresentationFn);
    g_origGetLocal = getLocalFn != 0 ? reinterpret_cast<GetLocalFn>(getLocalFn) : nullptr;
    g_getObserverTarget = getObsFn != 0 ? reinterpret_cast<GetObserverTargetFn>(getObsFn) : nullptr;
    g_getPlayerSlot =
        getPlayerSlotFn != 0 ? reinterpret_cast<GetPlayerSlotFn>(getPlayerSlotFn) : nullptr;
    g_origFindPlayerBySlot = findPlayerBySlotFn != 0
        ? reinterpret_cast<FindPlayerBySlotFn>(findPlayerBySlotFn)
        : nullptr;

    // --- locate FUN_18085b540 (IsSpectatorCheck) ---
    // Per-player icon colour path (FUN_180e460e0):
    //   entity = FUN_180926920(0);          // slot 0 = demo spectator controller
    //   if (!IsSpectatorCheck(entity) && !demoState())
    //       bVar2 = false;  // live: controller+0x850 colour index
    //   else
    //       bVar2 = true;   // spectator: team colour classes
    //
    // A shorter neighbour (FUN_1808490d0) also hits `cmp [rbx+0x3E7],1` but is
    // not the boolean spectator predicate — validate the full prologue.
    //
    // MSVC encodes `mov edi,eax` as either `8B F8` or `89 C7`.  The previous
    // pattern only accepted `89 C7` and therefore missed the live client
    // (PE 0x6A500273 uses `8B F8`).  Prefer the unique prologue+body mask.
    {
        auto tryAcceptIsSpec = [&](uintptr_t fnStart, const char* how) -> bool {
            if (fnStart == 0 || !IsInsideModule(client, fnStart)) {
                return false;
            }
            const auto* p = reinterpret_cast<const uint8_t*>(fnStart);
            // 48 89 5C 24 08 57 48 83 EC 20 48 8B D9
            if (!(p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24 &&
                  p[4] == 0x08 && p[5] == 0x57 && p[6] == 0x48 && p[7] == 0x83 &&
                  p[8] == 0xEC && p[9] == 0x20 && p[10] == 0x48 && p[11] == 0x8B &&
                  p[12] == 0xD9)) {
                return false;
            }
            // Body must still compare m_iTeamNum (== entity+0x3E7).
            bool hasTeamCmp = false;
            const size_t scan = ApproxFnSize(fnStart);
            for (size_t i = 0; i + 7 <= scan && i < 0x80; ++i) {
                if (p[i] == 0x80 && p[i + 1] == 0xBB && p[i + 2] == 0xE7 &&
                    p[i + 3] == 0x03 && p[i + 4] == 0x00 && p[i + 5] == 0x00 &&
                    p[i + 6] == 0x01) {
                    hasTeamCmp = true;
                    break;
                }
            }
            if (!hasTeamCmp) {
                return false;
            }
            g_origIsSpectatorCheck = reinterpret_cast<IsSpectatorCheckFn>(fnStart);
            Log("Radar POV: IsSpectatorCheck @ %p (%s)", reinterpret_cast<void*>(fnStart), how);
            return true;
        };

        // Primary: unique masked prologue —
        //   mov [rsp+8],rbx; push rdi; sub rsp,20h; mov rbx,rcx;
        //   lea rcx,[rip+disp]; call ...; cmp byte ptr [rbx+3E7h],1
        // RIP-relative LEA/CALL displacements are wildcards.
        if (client.base != nullptr && client.size >= 32) {
            for (size_t i = 0; i + 32 <= client.size; ++i) {
                const uint8_t* p = client.base + i;
                if (p[0] != 0x48 || p[1] != 0x89 || p[2] != 0x5C || p[3] != 0x24 ||
                    p[4] != 0x08 || p[5] != 0x57 || p[6] != 0x48 || p[7] != 0x83 ||
                    p[8] != 0xEC || p[9] != 0x20 || p[10] != 0x48 || p[11] != 0x8B ||
                    p[12] != 0xD9 || p[13] != 0x48 || p[14] != 0x8D || p[15] != 0x0D ||
                    p[20] != 0xE8 || p[25] != 0x80 || p[26] != 0xBB || p[27] != 0xE7 ||
                    p[28] != 0x03 || p[29] != 0x00 || p[30] != 0x00 || p[31] != 0x01) {
                    continue;
                }
                if (tryAcceptIsSpec(reinterpret_cast<uintptr_t>(p), "prologue+team-cmp mask")) {
                    break;
                }
            }
        }

        // Fallback: cmp [rbx+0x3E7],1 followed by either mov-edi encoding then jnz.
        //   80 BB E7 03 00 00 01  (8B F8 | 89 C7)  75 xx
        if (g_origIsSpectatorCheck == nullptr && client.base != nullptr) {
            const uint8_t kTeamCmp[] = {0x80, 0xBB, 0xE7, 0x03, 0x00, 0x00, 0x01};
            const uint8_t* search = client.base;
            size_t remaining = client.size;
            while (remaining >= sizeof(kTeamCmp) + 3) {
                const uint8_t* hit =
                    FindBytes(search, remaining, kTeamCmp, sizeof(kTeamCmp));
                if (hit == nullptr) {
                    break;
                }
                const uint8_t* after = hit + sizeof(kTeamCmp);
                const bool movEdi =
                    (after[0] == 0x8B && after[1] == 0xF8) ||  // mov edi, eax
                    (after[0] == 0x89 && after[1] == 0xC7);    // mov edi, eax (alt)
                if (movEdi && after[2] == 0x75) {
                    const uintptr_t fnStart =
                        FindFunctionStart(client, reinterpret_cast<uintptr_t>(hit));
                    if (tryAcceptIsSpec(fnStart, "team-cmp + mov edi,eax + jnz")) {
                        break;
                    }
                    Log("Radar POV: IsSpectatorCheck candidate @ %p rejected (fnStart=%p)",
                        hit, reinterpret_cast<void*>(fnStart));
                }
                const size_t advanced =
                    static_cast<size_t>(hit - client.base) + 1;
                if (advanced >= client.size) {
                    break;
                }
                search = client.base + advanced;
                remaining = client.size - advanced;
            }
        }

        // Structural fallback: icon renderer (called from radar players) does
        //   xor ecx,ecx; call getEntityBySlot; ...; call IsSpectatorCheck
        // Resolve the second call and validate its prologue.
        if (g_origIsSpectatorCheck == nullptr && radarPlayersFn != 0) {
            const auto playerCallsFull = CollectDirectCalls(radarPlayersFn, 0xC00);
            for (uintptr_t callee : playerCallsFull) {
                if (!IsInsideModule(client, callee)) {
                    continue;
                }
                const uint8_t* body = reinterpret_cast<const uint8_t*>(callee);
                const size_t bodySize = ApproxFnSize(callee);
                for (size_t i = 0; i + 10 < bodySize && i < 0x80; ++i) {
                    if (body[i] != 0x33 || body[i + 1] != 0xC9) {  // xor ecx,ecx
                        continue;
                    }
                    // First E8 after xor = getEntityBySlot(0); second distinct E8 nearby.
                    uintptr_t firstCall = 0;
                    uintptr_t secondCall = 0;
                    for (size_t j = i; j + 5 < bodySize && j < i + 0x40; ++j) {
                        uintptr_t target = 0;
                        if (!DecodeRel32Call(body + j, callee + j, target)) {
                            continue;
                        }
                        if (!IsInsideModule(client, target)) {
                            continue;
                        }
                        if (firstCall == 0) {
                            firstCall = target;
                        } else if (target != firstCall) {
                            secondCall = target;
                            break;
                        }
                        j += 4;
                    }
                    if (secondCall != 0 &&
                        tryAcceptIsSpec(secondCall, "radar-players icon-renderer call chain")) {
                        break;
                    }
                }
                if (g_origIsSpectatorCheck != nullptr) {
                    break;
                }
            }
        }

        if (g_origIsSpectatorCheck == nullptr) {
            Log("Radar POV: IsSpectatorCheck not found; per-player colours may stay team-based");
        }
    }

    // --- locate FUN_180926920 (GetEntityBySlot / controller-by-slot) ---
    // Icon colour path: xor ecx,ecx; call GetEntityBySlot; call IsSpectatorCheck.
    // Prefer that call-chain (avoids a near-identical helper that indexes a
    // different entity array).  Body shape: sub rsp,28h; cmp ecx,-1; ...
    // call [rax+310h]; mov rax,[rcx+rax*8]; ret.
    {
        auto looksLikeGetEntityBySlot = [&](uintptr_t fn) -> bool {
            if (!IsInsideModule(client, fn)) {
                return false;
            }
            const auto* p = reinterpret_cast<const uint8_t*>(fn);
            // Prologue + local-slot resolve + array load + ret (51 bytes).
            return p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC && p[3] == 0x28 &&
                p[4] == 0x83 && p[5] == 0xF9 && p[6] == 0xFF && p[7] == 0x75 &&
                p[8] == 0x17 && p[24] == 0xFF && p[25] == 0x90 && p[26] == 0x10 &&
                p[27] == 0x03 && p[28] == 0x00 && p[29] == 0x00 && p[42] == 0x48 &&
                p[43] == 0x8B && p[44] == 0x04 && p[45] == 0xC1 && p[46] == 0x48 &&
                p[47] == 0x83 && p[48] == 0xC4 && p[49] == 0x28 && p[50] == 0xC3;
        };

        // Primary: reverse from IsSpectatorCheck call sites.
        if (g_origIsSpectatorCheck != nullptr && client.base != nullptr) {
            const uintptr_t isSpec =
                reinterpret_cast<uintptr_t>(g_origIsSpectatorCheck);
            const uintptr_t base = reinterpret_cast<uintptr_t>(client.base);
            for (size_t i = 0; i + 5 < client.size; ++i) {
                if (client.base[i] != 0xE8) {
                    continue;
                }
                uintptr_t target = 0;
                if (!DecodeRel32Call(client.base + i, base + i, target) || target != isSpec) {
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
                        if (getEnt == isSpec || !looksLikeGetEntityBySlot(getEnt)) {
                            continue;
                        }
                        g_origGetEntityBySlot =
                            reinterpret_cast<GetEntityBySlotFn>(getEnt);
                        Log("Radar POV: GetEntityBySlot @ %p (via IsSpectatorCheck caller)",
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

        // Fallback: full body mask (may match a second similar helper — only
        // accept a unique hit, otherwise require the call-chain path above).
        if (g_origGetEntityBySlot == nullptr && client.base != nullptr &&
            client.size >= 0x33) {
            std::vector<uintptr_t> hits;
            for (size_t i = 0; i + 0x33 <= client.size; ++i) {
                const uintptr_t addr = reinterpret_cast<uintptr_t>(client.base + i);
                if (looksLikeGetEntityBySlot(addr)) {
                    hits.push_back(addr);
                }
            }
            if (hits.size() == 1) {
                g_origGetEntityBySlot = reinterpret_cast<GetEntityBySlotFn>(hits[0]);
                Log("Radar POV: GetEntityBySlot @ %p (unique body mask)",
                    reinterpret_cast<void*>(hits[0]));
            } else if (!hits.empty()) {
                Log("Radar POV: GetEntityBySlot body mask ambiguous (%zu hits); need call-chain",
                    hits.size());
            }
        }

        if (g_origGetEntityBySlot == nullptr) {
            Log("Radar POV: GetEntityBySlot not found; live colour paint may skip teammates");
        }
    }

    // --- locate FUN_180e39320 (SetRadarIconType) ---
    // Called from radar players after loading the subject's team byte.
    // Prologue (MSVC may emit REX on push rsi):
    //   40 56 57 41 56 48 83 EC 20 8B FA 4C 8B F1 E8 <getLocal>
    {
        constexpr size_t kCallGetLocalOff = 14;  // offset of E8 getLocal in prologue
        auto looksLikeSetIconType = [&](uintptr_t fn) -> bool {
            if (!IsInsideModule(client, fn) || !IsInsideModule(client, fn + 18)) {
                return false;
            }
            const auto* p = reinterpret_cast<const uint8_t*>(fn);
            // 40 56 57 41 56 48 83 EC 20 8B FA 4C 8B F1 E8
            return p[0] == 0x40 && p[1] == 0x56 && p[2] == 0x57 && p[3] == 0x41 &&
                p[4] == 0x56 && p[5] == 0x48 && p[6] == 0x83 && p[7] == 0xEC &&
                p[8] == 0x20 && p[9] == 0x8B && p[10] == 0xFA && p[11] == 0x4C &&
                p[12] == 0x8B && p[13] == 0xF1 && p[14] == 0xE8;
        };

        if (radarPlayersFn != 0 && g_origGetLocal != nullptr) {
            const auto* body = reinterpret_cast<const uint8_t*>(radarPlayersFn);
            const size_t bodySize = ApproxFnSize(radarPlayersFn);
            const uintptr_t getLocal = reinterpret_cast<uintptr_t>(g_origGetLocal);
            for (size_t i = 0; i + 5 < bodySize; ++i) {
                uintptr_t target = 0;
                if (!DecodeRel32Call(body + i, radarPlayersFn + i, target)) {
                    continue;
                }
                if (!looksLikeSetIconType(target)) {
                    continue;
                }
                uintptr_t firstCall = 0;
                const auto* cand = reinterpret_cast<const uint8_t*>(target);
                if (DecodeRel32Call(cand + kCallGetLocalOff, target + kCallGetLocalOff, firstCall) &&
                    firstCall == getLocal) {
                    g_origSetRadarIconType = reinterpret_cast<SetRadarIconTypeFn>(target);
                    Log("Radar POV: SetRadarIconType @ %p (radar-players + getLocal prologue)",
                        reinterpret_cast<void*>(target));
                    break;
                }
            }
        }

        if (g_origSetRadarIconType == nullptr && client.base != nullptr) {
            for (size_t i = 0; i + 19 <= client.size; ++i) {
                const uintptr_t addr = reinterpret_cast<uintptr_t>(client.base + i);
                if (!looksLikeSetIconType(addr)) {
                    continue;
                }
                if (g_origGetLocal != nullptr) {
                    uintptr_t firstCall = 0;
                    if (!DecodeRel32Call(client.base + i + kCallGetLocalOff, addr + kCallGetLocalOff,
                                         firstCall) ||
                        firstCall != reinterpret_cast<uintptr_t>(g_origGetLocal)) {
                        continue;
                    }
                }
                g_origSetRadarIconType = reinterpret_cast<SetRadarIconTypeFn>(addr);
                Log("Radar POV: SetRadarIconType @ %p (prologue + getLocal)",
                    reinterpret_cast<void*>(addr));
                break;
            }
        }

        if (g_origSetRadarIconType == nullptr) {
            Log("Radar POV: SetRadarIconType not found; live teammate type 0x11 may block RGB colours");
        }
    }

    // --- FUN_180e460e0 (RadarIconColor) + helpers used for forced paint ---
    // Icon colour body: xor ecx,ecx; call GetEntityBySlot; ... call IsSpectatorCheck
    {
        if (g_origGetEntityBySlot != nullptr && g_origIsSpectatorCheck != nullptr &&
            client.base != nullptr) {
            const uintptr_t getEnt = reinterpret_cast<uintptr_t>(g_origGetEntityBySlot);
            const uintptr_t isSpec = reinterpret_cast<uintptr_t>(g_origIsSpectatorCheck);
            const uintptr_t base = reinterpret_cast<uintptr_t>(client.base);
            for (size_t i = 0; i + 5 < client.size; ++i) {
                if (client.base[i] != 0xE8) {
                    continue;
                }
                uintptr_t t = 0;
                if (!DecodeRel32Call(client.base + i, base + i, t) || t != isSpec) {
                    continue;
                }
                const size_t isSpecCall = i;
                const size_t backStart = isSpecCall > 0x40 ? isSpecCall - 0x40 : 0;
                bool sawGetEnt = false;
                for (size_t j = backStart; j + 5 < isSpecCall; ++j) {
                    uintptr_t gt = 0;
                    if (DecodeRel32Call(client.base + j, base + j, gt) && gt == getEnt) {
                        sawGetEnt = true;
                        break;
                    }
                }
                if (!sawGetEnt) {
                    continue;
                }
                // Walk back to TEST RDX,RDX prologue (not accepted by LooksLikePrologue).
                uintptr_t fn = 0;
                const size_t maxBack = isSpecCall > 0x120 ? 0x120 : isSpecCall;
                for (size_t back = 0x20; back < maxBack; ++back) {
                    const uint8_t* cand = client.base + isSpecCall - back;
                    if (cand[0] != 0x48 || cand[1] != 0x85 || cand[2] != 0xD2) {
                        continue;
                    }
                    if (isSpecCall > back) {
                        const uint8_t prev = client.base[isSpecCall - back - 1];
                        if (prev != 0xCC && prev != 0x90 && prev != 0xC3 && back < 0x80) {
                            continue;
                        }
                    }
                    fn = base + isSpecCall - back;
                    break;
                }
                if (fn == 0) {
                    continue;
                }
                const auto* p = reinterpret_cast<const uint8_t*>(fn);
                g_origRadarIconColor = reinterpret_cast<RadarIconColorFn>(fn);
                Log("Radar POV: RadarIconColor @ %p", reinterpret_cast<void*>(fn));

                // Extract FUN_180a732c0: mov ecx,[rsi+0x158]; call
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
        }
        if (g_origRadarIconColor == nullptr) {
            Log("Radar POV: RadarIconColor not found; cannot force competitive ARGB");
        }
    }

    // FUN_180849370 — cl_teammate_color_N ARGB table
    // 40 53 48 83 EC 20 48 8B D9 83 FA FF 7D
    {
        const uint8_t kPat[] = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9,
                                0x83, 0xFA, 0xFF, 0x7D};
        const uint8_t* hit = FindBytes(client.base, client.size, kPat, sizeof(kPat));
        if (hit != nullptr) {
            g_getCompColorArgb =
                reinterpret_cast<GetCompColorArgbFn>(reinterpret_cast<uintptr_t>(hit));
            Log("Radar POV: GetCompColorArgb @ %p", hit);
        } else {
            Log("Radar POV: GetCompColorArgb not found");
        }
    }

    // FUN_1808494d0 — returns [rcx+0x850] when game-rules/mode allow
    // 40 53 48 83 EC 20 48 8B D9 48 8B 0D ... E8 ... 84 C0 74 ... 8B 83 50 08 00 00
    {
        if (client.base != nullptr) {
            for (size_t i = 0; i + 32 <= client.size; ++i) {
                const uint8_t* p = client.base + i;
                if (p[0] != 0x40 || p[1] != 0x53 || p[2] != 0x48 || p[3] != 0x83 ||
                    p[4] != 0xEC || p[5] != 0x20 || p[6] != 0x48 || p[7] != 0x8B ||
                    p[8] != 0xD9 || p[9] != 0x48 || p[10] != 0x8B || p[11] != 0x0D) {
                    continue;
                }
                // Find mov eax,[rbx+0x850] within the short function.
                bool has850 = false;
                for (size_t j = 0; j + 6 < 0x40; ++j) {
                    if (p[j] == 0x8B && p[j + 1] == 0x83 && p[j + 2] == 0x50 &&
                        p[j + 3] == 0x08 && p[j + 4] == 0x00 && p[j + 5] == 0x00) {
                        has850 = true;
                        break;
                    }
                }
                if (!has850) {
                    continue;
                }
                g_origGetCompTeammateColor =
                    reinterpret_cast<GetCompTeammateColorFn>(reinterpret_cast<uintptr_t>(p));
                Log("Radar POV: GetCompTeammateColor @ %p", p);
                break;
            }
        }
        if (g_origGetCompTeammateColor == nullptr) {
            Log("Radar POV: GetCompTeammateColor not found");
        }
    }

    // FUN_180863200 — competitive colour gate (localTeam, iconTeam)
    // 48 89 5C 24 10 57 48 83 EC 20 8B FA 8B D9 BA FF FF FF FF 48 8D 0D
    {
        const uint8_t kPat[] = {0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC,
                                0x20, 0x8B, 0xFA, 0x8B, 0xD9, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF,
                                0x48, 0x8D, 0x0D};
        const uint8_t* hit = FindBytes(client.base, client.size, kPat, sizeof(kPat));
        if (hit != nullptr) {
            g_origShouldApplyCompColor =
                reinterpret_cast<ShouldApplyCompColorFn>(reinterpret_cast<uintptr_t>(hit));
            Log("Radar POV: ShouldApplyCompColor @ %p", hit);
        } else {
            Log("Radar POV: ShouldApplyCompColor not found");
        }
    }

    return true;
}

void ResetResolvedRadarState()
{
    g_origRadarUpdate = nullptr;
    g_origRadarPresentation = nullptr;
    g_origRadarDemoState = nullptr;
    g_origGetLocal = nullptr;
    g_getObserverTarget = nullptr;
    g_getPlayerSlot = nullptr;
    g_origFindPlayerBySlot = nullptr;
    g_origIsSpectatorCheck = nullptr;
    g_origGetEntityBySlot = nullptr;
    g_origSetRadarIconType = nullptr;
    g_origRadarIconColor = nullptr;
    g_origShouldApplyCompColor = nullptr;
    g_origGetCompTeammateColor = nullptr;
    g_getCompColorArgb = nullptr;
    g_resolvePlayerByIndex = nullptr;
    g_spectatorFilterHooked = false;
    g_getEntityBySlotHooked = false;
    g_iconTypeHooked = false;
    g_iconColorHooked = false;
    g_compColorGateHooked = false;
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
    void* presentationTarget = reinterpret_cast<void*>(g_origRadarPresentation);
    void* demoStateTarget = nullptr;
    void* getLocalTarget = reinterpret_cast<void*>(g_origGetLocal);
    void* findPlayerBySlotTarget = reinterpret_cast<void*>(g_origFindPlayerBySlot);

    if (!CreateAndEnableHook(updateTarget, reinterpret_cast<void*>(&Hook_RadarUpdate),
                             reinterpret_cast<void**>(&g_origRadarUpdate), "radar_update")) {
        AbortInstall();
        return false;
    }

    if (getLocalTarget != nullptr && g_getObserverTarget != nullptr) {
        if (!CreateAndEnableHook(getLocalTarget, reinterpret_cast<void*>(&Hook_GetLocal),
                                 reinterpret_cast<void**>(&g_origGetLocal), "getLocal")) {
            Log("Radar POV: getLocal hook failed");
            AbortInstall();
            return false;
        }
    } else {
        Log("Radar POV: getLocal/getObs unresolved");
        AbortInstall();
        return false;
    }

    if (!CreateAndEnableHook(presentationTarget, reinterpret_cast<void*>(&Hook_RadarPresentation),
                             reinterpret_cast<void**>(&g_origRadarPresentation),
                             "radar_presentation")) {
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

    if (findPlayerBySlotTarget != nullptr && g_getPlayerSlot != nullptr) {
        if (!CreateAndEnableHook(findPlayerBySlotTarget, reinterpret_cast<void*>(&Hook_FindPlayerBySlot),
                                 reinterpret_cast<void**>(&g_origFindPlayerBySlot),
                                 "findPlayerBySlot")) {
            Log("Radar POV: spectator-slot filter unavailable; retaining engine player list");
            g_origFindPlayerBySlot = reinterpret_cast<FindPlayerBySlotFn>(findPlayerBySlotTarget);
        } else {
            g_spectatorFilterHooked = true;
        }
    } else {
        Log("Radar POV: spectator-slot filter unresolved; retaining engine player list");
    }

    // FUN_18085b540 is the per-entity spectator check that the player-icon
    // renderer pairs with the engine demo-state virtual.  Returning false
    // during POV frames lets the engine choose per-player colour classes.
    if (g_origIsSpectatorCheck != nullptr) {
        if (!CreateAndEnableHook(reinterpret_cast<void*>(g_origIsSpectatorCheck),
                                 reinterpret_cast<void*>(&Hook_IsSpectatorCheck),
                                 reinterpret_cast<void**>(&g_origIsSpectatorCheck),
                                 "isSpectatorCheck")) {
            Log("Radar POV: IsSpectatorCheck hook failed; per-player colours may stay team-based");
            g_origIsSpectatorCheck = nullptr;
        }
    } else {
        Log("Radar POV: IsSpectatorCheck unresolved; per-player colours may stay team-based");
    }

    // Remap FUN_180926920(0/-1) to the observed player's controller so live
    // colour paint sees team 2/3 instead of spectator team 1.
    if (g_origGetEntityBySlot != nullptr) {
        if (!CreateAndEnableHook(reinterpret_cast<void*>(g_origGetEntityBySlot),
                                 reinterpret_cast<void*>(&Hook_GetEntityBySlot),
                                 reinterpret_cast<void**>(&g_origGetEntityBySlot),
                                 "getEntityBySlot")) {
            Log("Radar POV: GetEntityBySlot hook failed; live colour paint may skip teammates");
            g_origGetEntityBySlot = nullptr;
        } else {
            g_getEntityBySlotHooked = true;
        }
    } else {
        Log("Radar POV: GetEntityBySlot unresolved; live colour paint may skip teammates");
    }

    // Map live teammate icon type 0x11 → 9/0xD so e460e0 competitive RGB runs.
    if (g_origSetRadarIconType != nullptr) {
        if (!CreateAndEnableHook(reinterpret_cast<void*>(g_origSetRadarIconType),
                                 reinterpret_cast<void*>(&Hook_SetRadarIconType),
                                 reinterpret_cast<void**>(&g_origSetRadarIconType),
                                 "setRadarIconType")) {
            Log("Radar POV: SetRadarIconType hook failed; type 0x11 may block RGB colours");
            g_origSetRadarIconType = nullptr;
        } else {
            g_iconTypeHooked = true;
        }
    } else {
        Log("Radar POV: SetRadarIconType unresolved; type 0x11 may block RGB colours");
    }

    // Open native competitive-colour gates during POV.
    if (g_origShouldApplyCompColor != nullptr) {
        if (CreateAndEnableHook(reinterpret_cast<void*>(g_origShouldApplyCompColor),
                                reinterpret_cast<void*>(&Hook_ShouldApplyCompColor),
                                reinterpret_cast<void**>(&g_origShouldApplyCompColor),
                                "shouldApplyCompColor")) {
            g_compColorGateHooked = true;
        } else {
            Log("Radar POV: ShouldApplyCompColor hook failed");
        }
    }
    if (g_origGetCompTeammateColor != nullptr) {
        if (!CreateAndEnableHook(reinterpret_cast<void*>(g_origGetCompTeammateColor),
                                 reinterpret_cast<void*>(&Hook_GetCompTeammateColor),
                                 reinterpret_cast<void**>(&g_origGetCompTeammateColor),
                                 "getCompTeammateColor")) {
            Log("Radar POV: GetCompTeammateColor hook failed");
        }
    }

    // Final paint: force competitive ARGB onto icon panels after native update.
    if (g_origRadarIconColor != nullptr && g_getCompColorArgb != nullptr) {
        if (CreateAndEnableHook(reinterpret_cast<void*>(g_origRadarIconColor),
                                reinterpret_cast<void*>(&Hook_RadarIconColor),
                                reinterpret_cast<void**>(&g_origRadarIconColor),
                                "radarIconColor")) {
            g_iconColorHooked = true;
        } else {
            Log("Radar POV: RadarIconColor hook failed; cannot force competitive ARGB");
        }
    } else {
        Log("Radar POV: RadarIconColor/ARGB helpers incomplete (iconColor=%p argb=%p resolve=%p)",
            reinterpret_cast<void*>(g_origRadarIconColor),
            reinterpret_cast<void*>(g_getCompColorArgb),
            reinterpret_cast<void*>(g_resolvePlayerByIndex));
    }

    g_installed.store(true, std::memory_order_release);
    Log("Radar POV: installed (enabled=%d radarUpdate=%d presentation=%d demoState=%d getLocal=%d getObs=%d spectatorFilter=%d isSpecCheck=%d getEntityBySlot=%d iconType=%d compGate=%d iconColor=%d) — self type is "
        "PAWN not controller",
        g_enabled.load() ? 1 : 0,
        g_origRadarUpdate != nullptr ? 1 : 0,
        g_origRadarPresentation != nullptr ? 1 : 0,
        g_origRadarDemoState != nullptr ? 1 : 0,
        g_origGetLocal != nullptr ? 1 : 0,
        g_getObserverTarget != nullptr ? 1 : 0,
        g_spectatorFilterHooked ? 1 : 0,
        g_origIsSpectatorCheck != nullptr ? 1 : 0,
        g_getEntityBySlotHooked ? 1 : 0,
        g_iconTypeHooked ? 1 : 0,
        g_compColorGateHooked ? 1 : 0,
        g_iconColorHooked ? 1 : 0);
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
    // Prefer FOG when POV works; the outer radar update restores show-all if
    // an observer target is unavailable.
    queueCmd("cl_radar_show_all_players_when_spectating 0");
    queueCmd("cl_radar_square_when_spectating 0");
    // Competitive teammate palette (1 = colours, 2 = colours + letters).
    queueCmd("cl_teammate_colors_show 1");
}
