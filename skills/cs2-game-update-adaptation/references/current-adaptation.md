# Current adaptation record

## Scope

Repository: `cs2-server-plugin`.

Purpose: maintain the native `server.dll` plugin across CS2 interface changes while preserving the external CS2 Highlight Tool protocol.

## Required sources

| Source | Role | How to use it |
| --- | --- | --- |
| `cs2-server-plugin/cs2-server-plugin/deps/hl2sdk` | Pinned build dependency for plugin headers, `convar.cpp`, and libraries. | Initialize recursively before building; do not silently move the gitlink during an ABI fix. |
| `advancedfx/advancedfx` | Working HLAE implementation for the same CS2 build. | Inspect `AfxHookSource2/main.cpp` and relevant commits for live interface behavior. It is evidence, not a drop-in dependency. |
| `advancedfx/advancedfx-prop` | Source 2 reverse-engineered interface definitions used by advancedfx. | Inspect the `prop` branch revision pinned by the matching advancedfx checkout, especially `cs2/sdk_src/public/icvar.h`, `tier1/convar.h`, and `cdll_int.h`. |

Use an exact checked-out revision. Record each revision and the CS2 update date below when changing ABI-sensitive code.

## Known-good state: v0.0.4

Date: 2026-07-11. CS2 update identifier used by the previous change: advancedfx update #1186.

### Client/demo interface changes already adopted

- `IDemoFile::GetDemoStartTick` is slot 2 and `GetDemoTick` is slot 3.
- `ISource2EngineToClient::GetDemoFilePath` is slot 43.
- `ExecuteClientCmd` is slot 51; `GetScreenSize` is slot 61; `GetDemoFile` is slot 69.
- Work on `ClientFrameStage_t::FRAME_RENDER_PASS` (value 12), not the older `FRAME_START` value.
- `ISource2Client::FrameStageNotify` remains vtable slot 36 in the advancedfx implementation reviewed for this update.

These declarations live in `cs2-server-plugin/cdll_interfaces.h` and must be re-verified for every future CS2 update.

### CVar startup-crash fix

Symptom: `csdm.log` ended at `CreateInterface called with Source2ServerConfig001`; the game exited before WebSocket startup.

Cause hypothesis confirmed by the successful v0.0.4 test: the old HL2SDK `ConCommandRef` / `ConVarRefAbstract` wrappers no longer safely enumerated current CS2 CVar data during `Connect()`.

Replacement: `cs2_cvar_access.h` models only the current `VEngineCvar007` ABI needed for unhide:

- `GetCvar(size_t)` is vtable slot 41;
- `GetCmd(size_t)` is vtable slot 44;
- `CS2CvarEntry::flags` is offset `0x30`;
- `CS2CommandEntry::flags` is offset `0x10`;
- scan at most 8192 entries and stop on null; commands also stop at the observed `0x400` terminator.

This follows advancedfx-prop commit `2e1366353c50d40150276c5d580b0eecb183881b`, as pinned by the reviewed advancedfx checkout. Re-verify these values against the matching current prop revision before changing them.

### Startup log checkpoints

`main.cpp` writes these checkpoints; use the final line to identify the failing phase:

1. `CreateInterface called with Source2ServerConfig001`
2. `Source2ServerConfig001::Connect entered`
3. `Source2ServerConfig001::Connect returned ...`
4. `VEngineCvar007 lookup returned ...`
5. `CVar unhide complete: ...`
6. `Registering CSDM console commands` / `Registered CSDM console commands`
7. `Starting WebSocket connection thread`

If the failure moves beyond checkpoint 5, investigate the legacy `ConVar_Register()` path next. Do not blame a WebSocket disconnect until checkpoint 7 is reached and source shows an exit path.

## Update record template

Append one row after every game-compatibility change. Keep it factual and link to the exact commit or log stored in the repository when available.

| Date / CS2 build | advancedfx commit | prop commit | Changed ABI | Evidence and test result | Follow-up |
| --- | --- | --- | --- | --- | --- |
| 2026-07-11 / #1186 | `facaa10c34e0d4c526e49ea9db949e6b55bae9a8` | `2e1366353c50d40150276c5d580b0eecb183881b` | Demo slots, render frame stage, VEngineCvar007 enumeration | v0.0.4 Windows build and game startup passed | Re-check `ConVar_Register()` on a later CVar ABI change |
