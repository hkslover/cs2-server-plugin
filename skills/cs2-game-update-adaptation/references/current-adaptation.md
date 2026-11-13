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
| 2026-10-08 / client.dll PE `0x6AC410BA`→`0x6AC7FFFA` | n/a (radar-POV local RE) | n/a | radar-POV only: mode fn inlined into `radar_update` (cvar read via ConVar-object-adjacent pointer slot, value `+0x58`); vtable/field offsets `IsPlayerPawn +0x4D8→0x4F0`, `IsObserver +0xAA0→0xAC0`, observer services `+0x1220→0x1308`, `m_iCompTeammateColor +0x850→0x858`, `m_bPawnIsAlive +0x91C→0x934`, life-state `+0x6EC→0x6F4`, show-all flag `0x17760→0x17808`; resolver chains rebuilt for the inlined mode; radar_update fault recovery + auto-disable + faultRip diagnostics after a one-off iconColor AV incident | Offline static resolver validation PASS on both PEs (`tools/run-radar-resolver-check.sh`, every step unique; structural offsets identical across the two builds); CI Windows build passed; in-game competitive-demo POV validation PASSED on PE `0x6AC7FFFA` (2026-10-10, healthy log captured) | None — recorded in `skills/radar-pov-maintenance/references/current-implementation.md` |
| 2026-11-13 / adapting to CS2 2026-11-11 update (exact game build not supplied) | `41b158171b275f9bb8ead737e8c7d0a159daf0af` (Nov 7 reference; predates game update) | `43f0981bd7a970b783b8d94f85feb6adc45fc229` (pinned by that advancedfx revision) | `ExecuteClientCmd` slot 51 now declared with 5 args; engine status slots 38/39/40/44; forward Shutdown's `this` argument | Matched cs-demo-manager `63257efa0dc3bd26d37d1e06ff2a00ae948a1a8f`, inspected at HEAD `f517fb08642829228e67a0864ad1db7fc3acd8ef`. Native macOS core ABI fixture (default + `-O2`), playback and protocol regressions PASS; `git diff --check` PASS | Windows/MSVC DLL build and same-Demo recording/exit test NOT RUN; exact CS2/HLAE runtime versions and crash dump absent. No radar adaptation |

## November 2026 core adaptation (game acceptance pending)

### Incident evidence

Input: repository-root `producews-export-20261113-230909.747.txt` (user-supplied,
untracked). Use its November 13 incident at lines 665 onward and final plugin log;
the export also contains older October incidents that are separate sessions.

- November 13 23:08:29: connection established, `playdemo` accepted, `status` and
  `demo_started` received. The WebSocket handler sends `status` on receipt, then
  loads the JSON, queues the command and sends `demo_started`, before engine playback.
- Plugin startup passed CVar unhide (469 commands / 1395 cvars), command registration
  and the WebSocket thread. `ClientFullyConnect` and the frame hook also ran.
- Last plugin lines: `Executed queued command: playdemo ...`, then
  `Executed queued command: demo_ui_mode 0`, then `Executed queued command: sv_cheats 1`.
  No tick/recording boundary was reported. The next unlogged path queries the Demo.
- At 23:08:39 the remote peer forcibly closed the connection (~9.68 seconds after
  connecting), then the host's 15-second reconnect grace expired. This establishes
  transport loss, not an independent WebSocket root cause or a confirmed crash stack.

### Source-backed changes and scope

1. [cs-demo-manager's November 11 compatibility commit](https://github.com/akiver/cs-demo-manager/commit/63257efa0dc3bd26d37d1e06ff2a00ae948a1a8f)
   adds `double flInputTime = NAN` and `uint64 nSDLTimestamp = 0` to
   `ExecuteClientCmd`, retaining slot 51. Its current declaration also agrees with
   advancedfx-prop's five-argument signature. The old three-argument declaration
   leaves the new arguments unspecified at the native boundary; returning from the
   call does not prove later queued engine processing is safe. This is a concrete
   compatibility bug and a plausible contributor to the incident, not a proven
   crash diagnosis without a dump/game rerun.
2. Match engine `GetMaxClients` / `IsInGame` / `IsConnected` to slots 38 / 39 / 40,
   and `IsRecordingDemo` to slot 44. Preserve Demo Windows slots 2/3/11/12,
   engine playback/path/object slots 42/43/69 and client frame hook slot 36.
3. Preserve work at frame stage 12: the supplied log proves that stage reached
   the command consumer, and the inspected advancedfx implementation uses it for
   its command system. Upstream CS:DM schedules at stage 0; changing our timing is
   not required by the observed failure. The advancedfx revision is a reference
   from before the update, not post-update game acceptance.
4. Forward `IAppSystem*` through the Shutdown hook; clear `g_pCVar` after unregister
   so static command destruction cannot call a stale interface. Return null from
   a failed server factory lookup before dereferencing its vtable; abort further
   plugin initialization when the original Connect fails.
5. Add a startup compatibility marker, engine lookup and frame hook diagnostics,
   and one-time logs bracketing initial Demo lookup/tick/playback queries. These
   make the next native failure boundary identifiable without per-frame logging.

The pinned HL2SDK gitlink remains `121f4d4d32d466d803283d1f50c812afea1bb3ce`.
CVar enumeration slots/fields were rechecked against the pinned prop reference
and left intact; startup also succeeded in the incident. Do not copy upstream's
SDK migration or its legacy enumeration into this repository as part of this fix.
Its network-message/protobuf and overlay/rendering changes serve features absent
from this plugin. `radar_pov` files and activation behavior are outside this change.
Linux Demo layout differences noted by upstream are not adapted by this Windows fix.
Dynamic `CSDM_WS_PORT`, production/debug wire messages and recording metadata remain
the same. No release or game-compatibility claim is made from the portable tests.

### Reproduce validation

From the repository root (write executables outside the checkout):

```sh
clang++ -std=c++14 -Wall -Wextra -Werror tests/core_interfaces_test.cpp -o /tmp/csdm-core-test
/tmp/csdm-core-test
clang++ -std=c++14 -O2 -Wall -Wextra -Werror tests/core_interfaces_test.cpp -o /tmp/csdm-core-test-opt
/tmp/csdm-core-test-opt
clang++ -std=c++14 -Wall -Wextra -Werror tests/debug_playback_test.cpp -o /tmp/csdm-playback-test
/tmp/csdm-playback-test
clang++ -std=c++14 -Wall -Wextra -Werror -Ics2-server-plugin/deps/json/include tests/debug_protocol_test.cpp cs2-server-plugin/record_status_bridge.cpp -o /tmp/csdm-protocol-test
/tmp/csdm-protocol-test
git diff --check
```

All passed locally on macOS. The core fixture independently numbers the native
slots and checks both default and explicit command metadata. It models the Windows
declarations; a native macOS pass does not establish Windows calling compatibility
or Linux CS2 support. Run the README's MSVC tests and Release x64 build on Windows,
then load the same Demo with radar disabled and check the first tick, recording
start/end, `demo_done`, next sequence/Demo and orderly session exit. If it fails,
retain the compatibility marker, final plugin log and game crash dump before
changing any further slots. Then separately verify debug play/pause/resume/record.
