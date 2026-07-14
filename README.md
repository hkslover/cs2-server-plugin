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

All `easywsclient` access is owned by the plugin's WebSocket thread. Other game/plugin threads enqueue bounded outbound events; `record_status`, `demo_started`, and `demo_done` are retained briefly and replayed on reconnect, while the generic `status` acknowledgement is intentionally never replayed.

After the host has completed a successful production queue, it may send
`end_produce_session` with a `request_id`. The plugin replies once with
`session_exit_ack` using that ID, drains the acknowledgement from its WebSocket
thread, then queues CS2's `quit` command on the game thread. This acknowledgement
is intentionally not replayed after reconnect; hosts without this protocol fall
back to their PID-close path.

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
