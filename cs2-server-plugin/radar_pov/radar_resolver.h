#pragma once

#include "../mem_utils.h"
#include "../radar_pov.h"

#include <cstddef>
#include <cstdint>

// Implementation guard: native plugin build (_WIN32) or the offline static
// resolver validation harness (RADAR_POV_RESOLVER_STATIC_TEST), which maps a
// client.dll file image and re-runs ResolveRadarFunctions unchanged.
#if defined(_WIN32) || defined(RADAR_POV_RESOLVER_STATIC_TEST)
#define RADAR_POV_RESOLVER_IMPL 1
#endif

namespace RadarPovResolver {

void SetLogger(RadarPovLogFn logger);

#ifdef RADAR_POV_RESOLVER_IMPL

using RadarUpdateFn = void(__fastcall*)(void* updateContext, uint8_t updateEnabled);
using GetLocalFn = void*(__fastcall*)();
using GetObserverTargetFn = void*(__fastcall*)(void* localPawn);
using GetPlayerSlotFn = void(__fastcall*)(void* pawn, int* outSlot);
using FindPlayerBySlotFn = void*(__fastcall*)(int slot);
using GetEntityBySlotFn = void*(__fastcall*)(int slot);
// MSVC x64: __fastcall is accepted but ignored (single x64 ABI), so the
// function pointer type omits it; identical to the engine-side call signature.
using IsSlotEnemyOfFn = uint8_t(*)(void* localPawn, int slot);
using SetRadarIconTypeFn = void(__fastcall*)(void* icon, int playerTeam);
using RadarIconColorFn = void(__fastcall*)(void* radar, void* icon);
using GetCompColorArgbFn = uint32_t*(__fastcall*)(uint32_t* outArgb, int colorIndex);
using ResolvePlayerByIndexFn = void*(__fastcall*)(int playerIndex);

struct ResolvedFunctions {
    RadarUpdateFn radarUpdate = nullptr;
    GetLocalFn getLocal = nullptr;
    GetObserverTargetFn getObserverTarget = nullptr;
    GetPlayerSlotFn getPlayerSlot = nullptr;
    FindPlayerBySlotFn findPlayerBySlot = nullptr;
    GetEntityBySlotFn getEntityBySlot = nullptr;
    IsSlotEnemyOfFn isSlotEnemyOf = nullptr;
    SetRadarIconTypeFn setRadarIconType = nullptr;
    RadarIconColorFn radarIconColor = nullptr;
    GetCompColorArgbFn getCompColorArgb = nullptr;
    ResolvePlayerByIndexFn resolvePlayerByIndex = nullptr;
};

struct ResolvedState {
    ResolvedFunctions functions;
    uintptr_t radarDemoStateGlobalSlot = 0;
    ptrdiff_t radarShowAllFlagOffset = 0;
};

#ifdef RADAR_POV_RESOLVER_IMPL
bool ResolveRadarFunctions(const MemUtils::ModuleInfo& client, ResolvedState& resolved);
#endif

#endif  // RADAR_POV_RESOLVER_IMPL

}  // namespace RadarPovResolver
