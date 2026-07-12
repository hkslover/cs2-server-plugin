#pragma once

#include "../mem_utils.h"
#include "../radar_pov.h"

#include <cstddef>
#include <cstdint>

namespace RadarPovResolver {

void SetLogger(RadarPovLogFn logger);

#ifdef _WIN32

using RadarUpdateFn = void(__fastcall*)(void* updateContext, uint8_t updateEnabled);
using GetLocalFn = void*(__fastcall*)();
using GetObserverTargetFn = void*(__fastcall*)(void* localPawn);
using GetPlayerSlotFn = void(__fastcall*)(void* pawn, int* outSlot);
using FindPlayerBySlotFn = void*(__fastcall*)(int slot);
using GetEntityBySlotFn = void*(__fastcall*)(int slot);
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

bool ResolveRadarFunctions(const MemUtils::ModuleInfo& client, ResolvedState& resolved);

#endif

}  // namespace RadarPovResolver
