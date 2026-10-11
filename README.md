# CS2 Server Plugin (Adapted for CS2 Highlight Tool)

This repository is a standalone distribution of the CS2 server plugin originally from [cs-demo-manager](https://github.com/akiver/cs-demo-manager), adapted to work with **cs2-highlight-tool-v2**.

## What was changed

Compared with the upstream CS2 plugin in `cs-demo-manager`, this repo includes integration updates for live production control:

- Added `record_status_bridge.h/.cpp` to isolate custom protocol logic from `main.cpp`.
- Added metadata-aware reporting for:
  - `mirv_streams record start`
  - `mirv_streams record end`
- Emits WebSocket events used by the tool UI/backend:
  - `record_status`
  - `demo_started`
  - `demo_done`

The goal is to keep plugin behavior compatible with upstream while enabling real-time recording state tracking in the external tool.

## Host integration environment

When launched by CS2 Highlight Tool, the host supplies the following optional environment variables:

- `CSDM_WS_PORT`: loopback WebSocket port for production control. If absent or invalid, the plugin keeps the standalone compatibility default of `4574`.
- `CSDM_LOG_PATH`: absolute path for the plugin diagnostic log. If absent, or if that path cannot be opened, the plugin falls back to `csdm.log` in its working directory.
- `CSDM_DEBUG_SESSION`: non-empty session id for the interactive debug workbench. Only when this is set does the plugin accept `debug_execute` and `debug_play_demo`; formal production launches omit it. Debug playback ignores Demo sequence files entirely.

All `easywsclient` access is owned by the plugin's WebSocket thread. Other game/plugin threads enqueue bounded outbound events; `record_status`, `demo_started`, and `demo_done` are retained briefly and replayed on reconnect, while the generic `status` acknowledgement is intentionally never replayed.

After the host has completed a successful production queue, it may send
`end_produce_session` with a `request_id`. The plugin replies once with
`session_exit_ack` using that ID, drains the acknowledgement from its WebSocket
thread, then queues CS2's `quit` command on the game thread. This acknowledgement
is intentionally not replayed after reconnect; hosts without this protocol fall
back to their PID-close path.

## Interactive debug protocol

Only active when `CSDM_DEBUG_SESSION` is non-empty. These messages are separate
from the production queue protocol and never touch the queue acknowledgement or
completion handlers.

- Plugin → `debug_session_ready` with `{session_id, protocol_version: 1}`. Sent
  once the WebSocket connection is open and the game-thread frame hook has
  resolved the engine and reached the command-consumption path,
  and resent on every reconnect. It does not mean a Demo is playing.
- The `FrameStageNotify` command hook is installed as soon as the client
  interface is available. Plugin `Connect` attempts installation; in debug
  mode a separate bootstrap worker retries every 100 ms until it succeeds or
  shutdown begins, without waiting for `ClientFullyConnect`. The worker only
  resolves the client interface and installs the hook. Engine lookup, readiness,
  and command execution stay on the game thread; WebSocket access stays on the
  WebSocket thread. Shutdown joins the bootstrap worker before engine teardown.
  `ClientFullyConnect` retains the production fallback. If the engine appears
  later, the frame hook retries lookup before announcing ready.
- Host → `debug_execute` with `{request_id, commands: [string]}`. Each element is
  one console command; a custom input keeps its semicolons and quotes inside a
  single element. The plugin trims whitespace and executes the commands in order
  on the game thread.
- Host → `debug_play_demo` with `{request_id, demo_path, commands?: [string]}`.
  Handled on the game thread: any queued sequences are cleared, the Demo is
  loaded with a quoted `playdemo "<demo_path>"`, and the optional draft commands
  are applied once the Demo can actually accept them. It never reads, writes or
  deletes `<demo>.json`; the `playdemo` production branch and the `+playdemo`
  launch option are likewise ignored while `CSDM_DEBUG_SESSION` is set. Plugin
  special actions in `commands` (for example `csdm_radar_pov 1`) are initialized
  immediately; ordinary Demo-dependent commands are deferred until the engine
  reports playback of the requested full path. Advancing ticks in the previous
  Demo do not consume these commands. Replaying the same file also requires an
  observed stop/start or tick rewind before applying them once.
- Plugin → `debug_command_result` with
  `{request_id, status: "executed"|"failed", error?}`. Sent after the game
  thread processed the whole request, not when the WebSocket received it.
  `executed` only means the commands were handed to the engine or the plugin's
  shared special-action entry; ordinary `ExecuteClientCmd` has no generic
  success signal.
- Plugin → `debug_demo_state` with `{session_id, demo_path, playing, tick}`.
  Sent on playback start/stop, an observed path change, or confirmation of an
  explicit replay, including requests without draft commands. Paths describe
  observed playback; queuing `playdemo` does not relabel the previous Demo.
  It does not end the debug game or re-issue playback after a reconnect.

Plugin special actions such as `csdm_radar_pov 0/1` are intercepted by the same
shared entry used by the automatic JSON sequence path. A failed special action
(for example a Radar POV hook install failure) is reported as `failed` with an
error instead of a silent success. A special action must be sent on its own: a
semicolon chain that starts with one is handed to the engine as a whole so no
trailing command is silently dropped.

## Build (Windows)

Requirements:

- Visual Studio 2022 Build Tools (MSBuild)
- Git with submodule support

Initialize submodules:

```bash
git submodule update --init --recursive
```

Build Release x64:

```powershell
msbuild /m /p:Configuration=Release /p:Platform=x64 cs2-server-plugin.sln
```

Output:

- `static/cs2/server.dll`

Run the portable playback-confirmation regression checks from a Visual Studio
Developer PowerShell (the test does not load CS2):

```powershell
cl /nologo /EHsc /W4 /WX tests/debug_playback_test.cpp "/Fo:$env:TEMP/csdm-debug-playback-test.obj" "/Fe:$env:TEMP/csdm-debug-playback-test.exe"
if ($LASTEXITCODE -ne 0) { throw "Playback regression test build failed" }
& "$env:TEMP/csdm-debug-playback-test.exe"
if ($LASTEXITCODE -ne 0) { throw "Playback regression test failed" }
```

The same test can be compiled with `clang++ -std=c++14` on macOS/Linux. These
checks cover path/replay confirmation; actual engine path reporting and command
application timing still require Windows HLAE/CS2 validation.

## Release automation

This repo has a GitHub Actions workflow that triggers on version tags (`v*`).

On tag push (example: `v0.0.1`), it will:

1. Build Windows `Release|x64`
2. Collect `static/cs2/server.dll`
3. Package it as `cs2-server-plugin-<tag>-windows.zip`
4. Create a GitHub Release and upload the zip asset

## Upstream attribution

Original plugin source and project ownership remain with the `cs-demo-manager` maintainers.

- Upstream project: <https://github.com/akiver/cs-demo-manager>

## License

MIT License (same as upstream project).
