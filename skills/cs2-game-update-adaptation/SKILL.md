---
name: cs2-game-update-adaptation
description: Update cs2-server-plugin after a Counter-Strike 2 game update breaks loading, crashes on startup, changes demo playback behavior, or requires Source 2 ABI/vtable/interface adaptation. Use to investigate and implement compatibility updates using the project's pinned HL2SDK plus advancedfx and advancedfx-prop as reference implementations, then validate, release, and record the new evidence for the next update.
---

# CS2 server-plugin update adaptation

Update the plugin from evidence, not from guessed vtable offsets. Read [references/current-adaptation.md](references/current-adaptation.md) before changing code; it records the current known ABI, dependencies, and prior incident.

## Workflow

1. Preserve unrelated work. Inspect `git status`, current branch, submodule state, local `csdm.log`, crash dumps, and the exact CS2/HLAE versions. Do not overwrite a user-built DLL.
2. Separate the failure phase using the startup order and logs:
   - `CreateInterface` / server library forwarding and server-side vtable hooks;
   - `Connect` / CVar access and command registration;
   - client `FrameStageNotify` hook and demo calls;
   - WebSocket connection and received messages.
   A WebSocket connection failure is not by itself a process-exit path. Verify it from source before attributing a crash to it.
3. Fetch or inspect the matching advancedfx and `advancedfx-prop` revisions. Compare concrete interfaces, enum values, and vtable indices used by `advancedfx/AfxHookSource2`; do not copy unrelated pattern-scan or rendering changes.
4. Compare each plugin assumption against the references: interface names, method order, object-field offsets, command/CVar registration ABI, and frame-stage value. Treat every hardcoded slot as unverified after a game update.
5. Make the smallest compatible change. Add diagnostic logs around every native boundary and null-check factory results. Keep WebSocket protocol behavior and the dynamic `CSDM_WS_PORT` contract intact unless evidence says it changed.
6. Validate source formatting and build on the target Windows/MSVC workflow. Test a minimal startup before demo playback, then demo playback, then a real recording. Capture the final `csdm.log` lines on failure.
7. Update `references/current-adaptation.md` in the same change with the CS2 build/date, exact evidence, affected interfaces, test result, and remaining unknowns. This is mandatory: it is how later updates improve the skill.

## Release

After the Windows build and game test pass, commit only related changes, merge as directed, and create the next `v*` tag on `main`. The tag-triggered release workflow packages `server.dll` and `changelog.xml`.

## Guardrails

- Never infer a server-side vtable slot from advancedfx's client-side hook.
- Never retain legacy `ConCommandRef` / `ConVarRefAbstract` iteration after an ABI change without re-verifying its handles.
- Do not claim ABI compatibility from a successful compile alone; require a Windows DLL build and in-game startup test.
- Prefer bounded iteration and explicit null checks over sentinel-only loops through game-owned memory.
