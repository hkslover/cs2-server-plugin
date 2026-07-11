#pragma once

// First-person radar simulation for CS2 demo spectating.
//
// Demo/GOTV radar defaults to "show everyone". The engine cvar
// cl_radar_show_all_players_when_spectating only toggles that bypass; when it
// is 0 the filter still uses the *local spectator* as the team/spotted
// reference, so teammates of the observed player disappear.
//
// This module hooks client.dll radar helpers so visibility is evaluated from
// the current observer target (spec_player) instead:
//   - teammates of the observed player stay visible
//   - enemies follow spotted rules
//   - the force-show-all flag is kept clear while POV mode is on
//
// Windows x64 only for now. Install is best-effort and must never crash the
// rest of the plugin if signatures fail after a game update.

#include <cstdarg>

using RadarPovLogFn = void (*)(const char* fmt, ...);

// Optional logger (e.g. main.cpp Log). Safe to leave unset.
void RadarPov_SetLogger(RadarPovLogFn logger);

// Default is enabled. Can be toggled before or after Install.
void RadarPov_SetEnabled(bool enabled);
bool RadarPov_IsEnabled();

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
