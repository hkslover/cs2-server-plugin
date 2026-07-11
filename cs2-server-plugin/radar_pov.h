#pragma once

// First-person radar simulation for CS2 demo spectating.
//
// Real radar player update (client.dll) uses getLocal() as "self". getLocal
// returns the local *player pawn* (validated with IsPlayerPawn @ vtable+0x4D8),
// NOT a controller. Team / slot / isEnemy / spotted all run on that pawn.
//
// While spectating, getLocal is the spectator pawn, so after show-all is off
// almost nobody is visible and radar_mode keeps spectator presentation. Fix:
// during the complete radar update, make getLocal return the *observer target
// pawn* (same type as live 1P self), including layout, sounds and icon state.
//
// If POV cannot be resolved, fall back to engine show-all so the radar is never
// empty. Never pass a controller into pawn APIs (that AV'd Hook_RadarPlayers).
//
// Windows x64 only. Install is best-effort / non-fatal.

#include <cstdarg>

using RadarPovLogFn = void (*)(const char* fmt, ...);

void RadarPov_SetLogger(RadarPovLogFn logger);

void RadarPov_SetEnabled(bool enabled);
bool RadarPov_IsEnabled();

bool RadarPov_Install();
void RadarPov_Uninstall();
bool RadarPov_IsInstalled();

void RadarPov_QueueEngineSetup(void (*queueCmd)(const char* cmd));
