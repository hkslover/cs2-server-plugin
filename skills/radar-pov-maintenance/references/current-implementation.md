# Radar POV: validated implementation reference

Last validated design: **7 MinHook detours**, teammate-only competitive colours,
no forced radar cvars. Revalidate after every CS2 `client.dll` update.

Code: `cs2-server-plugin/radar_pov.cpp`, `radar_pov.h`  
Related install: `main.cpp` (`RadarPov_Install` on `ClientFullyConnect`;
`csdm_radar_pov` console command).

## Target behavior

During demo first-person follow (`spec_mode` / `spec_player`):

| Item | Expected |
| --- | --- |
| Map rotation | Follows observed player (with radar rotate on) |
| Teammates | Distinct competitive colours (`cl_teammate_color_1..5` palette) |
| Enemies | Native treatment — **not** competitive multi-colour |
| Spotted / sound / death | Engine native markers |
| Freecam spectator | Not drawn as a player icon |
| Engine cvars | Plugin does **not** force radar/teammate cvars |

## Design summary

```text
Hook_RadarUpdate (scope)
  PreparePovContext:
    observed pawn, slot, team (from pawn m_iTeamNum @ +0x3E7)
  ├─ getLocal()                 → observed pawn
  ├─ GetEntityBySlot(0 / -1)    → observed controller slot
  ├─ demo/HLTV (+0x2B0)         → 0 (this frame only)
  ├─ findPlayerBySlot(spec)     → nullptr
  ├─ SetRadarIconType           → teammates only: type 0x11 → 9 (T) / 0xD (CT)
  └─ RadarIconColor (e460e0)
        native update
        then ForceCompetitiveIconColor (teammates only, engine ARGB palette)
```

### Why identity alone is not enough

| Step | Engine fact (Ghidra) |
| --- | --- |
| Colour local | `FUN_180e460e0` uses `GetEntityBySlot(0)`, not `getLocal` |
| Live branch | Needs `!IsSpectator(localCtrl) && !demo(+0x2B0)` |
| Live teammate type | `FUN_180e39320` sets type **`0x11`** for non-self same-team |
| Competitive RGB | `e460e0` paints `cl_teammate_color_*` only for types **`9` / `0xD`** |
| Demo reality | Netvars / gates often leave native paint as no-op → **force ARGB** after native |

### Explicitly removed (do not re-add without new evidence)

| Former hook | Why dropped |
| --- | --- |
| IsSpectatorCheck force 0 | Covered by identity remap + demo |
| Presentation selector force | Should follow identity + demo |
| shouldApplyCompColor (863200) | Covered by force-color path |
| getCompTeammateColor (8494d0) | Force path reads `+0x850` directly |
| QueueEngineSetup cvars | Empty; host/tool owns cvars |

## Hooks (7)

| # | Name (log) | Target role (last known RVA) | Required | Role |
| --- | --- | --- | --- | --- |
| 1 | `radar_update` | Outer update ~`0xE25550` | yes | Thread-local POV scope; show-all fail-safe |
| 2 | `getLocal` | ~`0xC10EA0` | yes | Observed **pawn** as self |
| 3 | `radar_demo_state` | Engine vtable `+0x2B0` | yes | Scoped non-demo |
| 4 | `getEntityBySlot` | ~`0x926920` | yes | Slot `0`/`-1` → observed controller slot |
| 5 | `findPlayerBySlot` | players-loop call site | yes (product) | Hide freecam spectator slot |
| 6 | `setRadarIconType` | ~`0xE39320` | yes (current) | Teammate `0x11` → `9`/`0xD` (panel set for colour) |
| 7 | `radarIconColor` | ~`0xE460E0` | yes (current) | After native: force teammate ARGB |

Helpers (not hooked): `getObs` (~`0x813F30`, pawn `+0x1220`), `getPlayerSlot`,
`GetCompColorArgb` (~`0x849370`), `ResolvePlayerByIndex` (~`0xA732C0`).

### `setRadarIconType` (what it does)

Native `FUN_180e39320(icon, playerTeam)` writes type at `icon+0x16c` and updates
panel visibility bits. Live identity makes allies type `0x11`. Competitive body
paint and the panels we SetColor (`+0x60/+0x68/+0x70` …) align with types
`9`/`0xD`. Hook runs **after** original: if POV + teammate + type `0x11`, set
`9` (T) or `0xD` (CT). Enemies unchanged.

### `radarIconColor` / force-color (what it does)

After native `FUN_180e460e0`: clear rate-limit float at `icon+0x14c`; resolve
controller; require `IsPovTeammateTeam`; read `m_iCompTeammateColor` (`+0x850`),
fallback `playerIndex % 5` if unset; `GetCompColorArgb` → SetColor on panels
`0x60,0x68,0x70,0x80,0x88,0x90` (same as native competitive paint).

### Teammate filter

- `g_povSelfTeam` from **observed pawn** `+0x3E7` first (controller-via-slot often
  reads `0` at setup — that previously failed closed and blocked all colours).
- Lazy refresh in `IsPovTeammateTeam` if still invalid.
- Never competitive-colour enemies.

## Last known-good anchors (PE `0x6A500273`)

| Role | RVA (image base `0x180000000`) | Rediscovery |
| --- | --- | --- |
| Outer radar update | `0xE25550` | Caller of mode + players; `test dl,dl` + `lea rsi,[rcx-20h]` |
| radar_mode | `0xE1F000` | From cvar `cl_radar_show_all_players_when_spectating` |
| Show-all flag | `radar+0x17760` | `and byte ptr [radar+off], ~1` in mode |
| Players loop | `0xE328A0` | Large call after mode in outer update |
| getLocal | `0xC10EA0` | Early call in players |
| getObs | `0x813F30` | Imm `0x1220` near start |
| GetEntityBySlot | `0x926920` | `xor ecx,ecx; call X` then `call IsSpectatorCheck` in icon colour |
| IsSpectatorCheck | `0x85B540` | Prologue + `cmp [rbx+0x3E7],1` (`mov edi,eax` may be `8B F8` or `89 C7`) |
| SetRadarIconType | `0xE39320` | `40 56 57 41 56 ... E8 getLocal` |
| RadarIconColor | `0xE460E0` | Starts `test rdx,rdx`; uses GetEntityBySlot(0) |
| GetCompColorArgb | `0x849370` | `cl_teammate_color_*` switch |
| m_iTeamNum | entity `+0x3E7` | Byte |
| m_iCompTeammateColor | controller `+0x850` | Int 0–4 or unset |

Prefer semantic re-resolve over these numbers after an update.

## Healthy log (success baseline)

```text
Radar POV: installed enabled=1 update=1 getLocal=1 getObs=1 demoState=1
  getEntityBySlot=1 spectatorFilter=1 iconType=1 forceColor=1
Radar POV: active — pawn ... -> observed ... (slot N team 2|3, spectatorSlot 0)
Radar POV: demo/HLTV state 1 -> 0 for radar frame
Radar POV: filtering demo spectator slot 0
Radar POV: GetEntityBySlot 0 -> observed slot N
Radar POV: force-color teammate type=9|13 team=T selfTeam=T netvar=... idx=... argb=0x... panels=6 playerIndex=...
```

Must **not** appear:

- `team 0` on active line after POV is stable (team read failed → no colours)
- `force-color` with `team != selfTeam` (enemy leak)
- `shouldApplyCompColor` / `getCompTeammateColor` MinHook lines (removed)
- `cl_radar_show_all_players_when_spectating` from plugin QueueEngineSetup (empty)

## Failure matrix

| Log / visual | Action |
| --- | --- |
| `getEntityBySlot=0` | Re-resolve `FUN_180926920` via icon-renderer call chain |
| `forceColor=0` | Re-resolve `e460e0` + `849370` |
| `active ... team 0` | Prefer pawn `+0x3E7`; fix `RefreshPovSelfTeam` |
| Allies solid team colour, no force-color lines | Hook not running or type filter excluding all |
| Enemies multi-coloured | `IsPovTeammateTeam` too loose |
| Extra freecam dot | `findPlayerBySlot` / wrong `g_spectatorSlot` |
| Install shape errors | Outer update / mode prologue masks |

## Update procedure after CS2 patch

1. Keep last good commit; capture new `csdm.log` + PE timestamp.
2. Ghidra: re-find outer update from cvar string, then mode, players, e460e0, e39320.
3. Update only broken resolvers; keep hook set unless proven reducible.
4. Build, demo test, update this file’s anchors + healthy log.
5. Do not force cvars in `QueueEngineSetup` unless product requires it.

## Product notes

- Default enabled on `ClientFullyConnect` when install succeeds.
- Console: `csdm_radar_pov 0|1`.
- Single-hook solution is **not** available with current engine structure (multiple independent local/demo queries + type/colour split).
