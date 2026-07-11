#pragma once

// First-person radar simulation for CS2 demo spectating.
//
// Strategy (minimal upstream hooks only):
// Real and demo radar share one client.dll path. During one radar update frame
// we rewrite only the inputs that every live-vs-spectator branch re-queries:
//
//   • getLocal()              → observed player pawn
//   • GetEntityBySlot(0/-1)   → observed player controller
//                               (icon colour does not use getLocal)
//   • engine demo/HLTV (+0x2B0) → false for this frame only
//   • findPlayerBySlot(spectator) → nullptr (optional, hide freecam icon)
//
// Native code then runs the normal live first-person layout, spots, and colours.
// No icon-type rewrites, no forced ARGB, no colour-gate detours.
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
