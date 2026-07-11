#pragma once

// First-person radar simulation for CS2 demo spectating.
//
// Upstream-only strategy (Ghidra):
// Competitive icon body colours are painted in FUN_180e460e0 when:
//   !IsSpectator(localCtrl) && !demo  AND  icon type is 9/0xD  AND  colour gates pass.
// Identity hooks open the live branch; icon-type + colour-gate hooks complete the
// engine's own competitive RGB path. No forced SetColor / ARGB paint.
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

// Kept for call-site compatibility; currently queues no engine commands.
void RadarPov_QueueEngineSetup(void (*queueCmd)(const char* cmd));
