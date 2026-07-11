#pragma once

// First-person radar simulation for CS2 demo spectating.
//
// Identity hooks (getLocal, GetEntityBySlot, demo) open the live radar branch.
// Teammate icon type rewrite + post-e460e0 force ARGB (engine cl_teammate_color_*)
// complete competitive colours for teammates only.
//
// Windows x64 only. Install is best-effort / non-fatal.

#include <cstdarg>

using RadarPovLogFn = void (*)(const char* fmt, ...);

void RadarPov_SetLogger(RadarPovLogFn logger);

// Runtime gate for hooks. Enabled from sequence JSON action "csdm_radar_pov"
// (main.cpp); install is idempotent — duplicate JSON actions are ignored.
void RadarPov_SetEnabled(bool enabled);
bool RadarPov_IsEnabled();

bool RadarPov_Install();
void RadarPov_Uninstall();
bool RadarPov_IsInstalled();

// Kept for call-site compatibility; currently queues no engine commands.
void RadarPov_QueueEngineSetup(void (*queueCmd)(const char* cmd));
