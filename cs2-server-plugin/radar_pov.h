#pragma once

// First-person radar simulation for CS2 demo spectating.
//
// Real non-spectator radar path in client.dll (CCSGO_HudRadar player update):
//   getLocal() -> local *controller*
//   getSlot(controller) / getTeam(controller) / isEnemy(controller, slot)
//   enemies only when spotted; teammates always shown
//
// Demo/GOTV spectating uses the spectator controller as "self", so after
// clearing show-all the filter is wrong (no teammates of the observed player).
//
// Fix: while the radar player-icon update runs, hook getLocal so it returns the
// *observed player's controller* (pawn.m_hController), matching live 1P.
// Show-all flag is forced off. Do NOT pass observer *pawn* into isEnemy/getSlot
// (those APIs expect a controller — that crash path is retired).
//
// Windows x64 only. Install is best-effort and must never crash the rest of the
// plugin if signatures fail after a game update.

#include <cstdarg>

using RadarPovLogFn = void (*)(const char* fmt, ...);

void RadarPov_SetLogger(RadarPovLogFn logger);

// Default is enabled. Can be toggled before or after Install.
void RadarPov_SetEnabled(bool enabled);
bool RadarPov_IsEnabled();

// Legacy flag kept for csdm_radar_pov compatibility. No longer installs the
// crashy is_enemy/get_slot pawn redirects; true POV is always via getLocal.
void RadarPov_SetAggressiveRedirects(bool enabled);
bool RadarPov_AggressiveRedirectsEnabled();

// Resolve client.dll radar functions and install hooks.
// Returns true if hooks are active. Failures are logged and non-fatal.
bool RadarPov_Install();

// Remove hooks (safe to call if never installed / already removed).
void RadarPov_Uninstall();

// True after a successful Install that has not been uninstalled.
bool RadarPov_IsInstalled();

// Apply supporting engine cvars (show-all off, circular radar when spectating).
// Call from the engine thread (e.g. via QueueEngineCommand).
void RadarPov_QueueEngineSetup(void (*queueCmd)(const char* cmd));
