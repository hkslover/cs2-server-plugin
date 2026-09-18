# Radar POV: validated implementation reference

Last validated design: **8 MinHook detours**, teammate-only competitive colours,
no forced radar cvars. Revalidate after every CS2 `client.dll` update.

Validated in-game on PE `0x6AA1AE5E` (2026-09-18): demo POV shows teammates in
competitive colours, enemies only when spotted, no freecam dot. Runtime sample
in the "Healthy log" section below.

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
    → observer-chain model: getObs(local) pawn
    → direct-local fallback: getLocal() already IS the POV player pawn
      (no observer chain; newer demo playback) — use it as self
  ├─ getLocal()                 → observed pawn
  ├─ GetEntityBySlot(0 / -1)    → observed controller slot
  ├─ demo/HLTV (+0x2B0 = IVEngineClient::IsHLTV) → 0 (this frame only)
  ├─ findPlayerBySlot(spec)     → nullptr
  ├─ IsSlotEnemyOf (0x8B0E00)   → live team gate (see below)
  ├─ SetRadarIconType           → teammates only: type 0x11 → 9 (T) / 0xD (CT)
  │                               + comp-allowed bit [icon+0x17D] |= 8
  └─ RadarIconColor (e62bc0)
        native update
        then ForceCompetitiveIconColor (teammates only, engine ARGB palette)
```

The direct-local fallback triggers only when the observer chain fails to
resolve a pawn AND `getLocal()` itself is a live player pawn on team T/CT.
Without it, that build silently degrades to the show-all fail-safe (native
demo radar) — i.e. the feature appears completely inactive.

### The teammate-hiding cvar (confirmed from runtime log, PE 0x6AA1AE5E)

A runtime-registered ConVar ref (object `0x182339278`, name not statically
extractable) reads **non-zero during demo playback**. It has three effects:

1. `IsSlotEnemyOf` (0x8B0E00) early-returns true for every non-self slot →
   the players-loop draw gate hides unspotted **teammates** (enemies behave
   correctly by accident — they are spotted-gated in live too). The POV
   player's own icon still shows via the obsTarget==pawn check.
2. `SetRadarIconType` gives same-team icons type 0x11 (solid dot) instead of
   9/0xD — handled by the type rewrite.
3. The players loop skips the `[icon+0x17D] |= 8` "comp colours allowed" bit —
   set by the rewrite hook.

The **IsSlotEnemyOf hook** restores the live branch during POV frames:
`(team(player) != selfTeam)`, so teammates always draw and enemies stay
spotted-gated.

**Argument space (important):** the players loop does *not* pass the raw slot —
it passes the converted player index from `0x180a8baa0` (the
`ResolvePlayerByIndex` space, produced via `0x180917ea0`). The hook must
resolve with `ResolvePlayerByIndex` (`0xA8C160`) exactly like the native gate
does; calling `findPlayerBySlot` on that value returns null, which silently
falls back to the native teammate-hiding path (this was the "teammates missing"
bug). A team-validated `findPlayerBySlot` fallback is kept.

### Second hiding mechanism: m_bPawnIsAlive (icon state flags)

Players loop (`0xE4EF90`) per icon:

| Condition | Effect |
| --- | --- |
| `[player+0x6EC]` ∉ {0,3} | dead/dying path `0xE4F867` — position/fade only, no gate, no colour |
| `m_bPawnIsAlive` (`[player+0x91C]`) == 0 | sets icon `+0x17C` bit `0x20` (hidden), skips drawing |
| `+0x17C` bit `0x20` set while alive | clears it, skips one frame, then draws |
| otherwise | draw gate `IsSlotEnemyOf` → teammates draw, enemies spotted-gated |

`m_bPawnIsAlive` at `+0x91C` was confirmed from the client schema table
(`lea rdx, str.m_bPawnIsAlive` + offset `0x91C` at `0x1808683E3`). Dead
teammates legitimately do not draw (live behaviour) — check the alive state
before diagnosing a "missing teammates" report.

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

## Hooks (8)

| # | Name (log) | Target role (RVA, PE `0x6AA1AE5E`) | Required | Role |
| --- | --- | --- | --- | --- |
| 1 | `radar_update` | Outer update `0xE408D0` (vtable `CCSGO_HudRadar` +`0x2E0`) | yes | Thread-local POV scope; show-all fail-safe |
| 2 | `getLocal` | `0xC29DA0` | yes | Observed **pawn** as self |
| 3 | `radar_demo_state` | Engine vtable `+0x2B0` (`IsHLTV`) | yes | Scoped non-demo |
| 4 | `getEntityBySlot` | `0x93F780` | yes | Slot `0`/`-1` → observed controller slot |
| 5 | `findPlayerBySlot` | `0xA8BDC0` (players-loop call site) | yes (product) | Hide freecam spectator slot |
| 6 | `isSlotEnemyOf` | `0x8B0E00` (players-loop call site) | yes | Live team gate; teammates always drawn |
| 7 | `setRadarIconType` | `0xE55E00` | yes (current) | Teammate `0x11` → `9`/`0xD` + comp-allowed bit |
| 8 | `radarIconColor` | `0xE62BC0` | yes (current) | After native: force teammate ARGB |

Helpers (not hooked): `getObs` (`0x82C770`, pawn `+0x1220`), `getPlayerSlot`
(`0x918130`), `GetCompColorArgb` (`0x861BB0`), `ResolvePlayerByIndex`
(`0xA8C160`).

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

## Last known-good anchors (PE `0x6AA1AE5E`, build 2026-09-09)

Resolver re-validated statically against this build (2026-09-17, radare2):
every step of `ResolveRadarFunctions` resolves uniquely and all struct
offsets are identical to the previous build. Only code RVAs moved.

| Role | RVA (image base `0x180000000`) | Rediscovery |
| --- | --- | --- |
| Outer radar update (vtable `CCSGO_HudRadar` +`0x2E0`) | `0xE408D0` | Caller of mode + players; `test dl,dl` + `lea rsi,[rcx-20h]` |
| radar_mode | `0xE3A380` | From cvar `cl_radar_show_all_players_when_spectating` (ConVar obj `0x1823E0100`) |
| Show-all flag | `radar+0x17760` bit0 | `and byte ptr [radar+off], ~1` clear / `or ...1` set in mode |
| Spotted/heard bitmask | `radar+0x17770` | per-slot bit; writer fn `0xE4CC30` (sound/radio events) |
| Players loop | `0xE4EF90` | Post-mode call in outer update; getPlayerSlot+findPlayerBySlot structure |
| getLocal | `0xC29DA0` | Early call in players / mode / setRadarIconType |
| getObs (observer target pawn) | `0x82C770` | `mov rcx,[rcx+0x1220]` → services → `[+0x100]` |
| GetEntityBySlot | `0x93F780` | `xor ecx,ecx; call` then `call IsSpectatorCheck` in icon colour |
| IsSpectatorCheck | `0x873D80` | Prologue + `cmp [rbx+0x3E7],1` |
| IsSpectator(pawn) | `0x8B0F00` | `mov edx,[rcx+0x13D0]` handle resolve (mode / icon type) |
| SetRadarIconType | `0xE55E00` | `40 56 57 41 56 ... E8 getLocal` |
| RadarIconColor | `0xE62BC0` | Starts `test rdx,rdx`; uses GetEntityBySlot(0) |
| GetCompColorArgb | `0x861BB0` | `cl_teammate_color_*` switch |
| GetCompTeammateColor (netvar read) | `0x861D10` | Returns `m_iCompTeammateColor` or -1 (gate `[0x1823CC6C8]`) |
| ResolvePlayerByIndex | `0xA8C160` | `mov ecx,[rsi+0x158]; call` in icon colour |
| getPlayerSlot | `0x918130` | `lea rdx,[rsp+24]; mov rcx,rax; call` in players |
| findPlayerBySlot | `0xA8BDC0` | `mov ecx,edi; call` in players |
| IsSlotEnemyOf (draw gate) | `0x8B0E00` | in players: `mov edx,[rsp+28]; mov rcx,[rsp+38]; call` |
| m_bPawnIsAlive (bool) | controller `+0x91C` | Schema entry at `0x1808683E3` (`str.m_bPawnIsAlive`) |
| Life-state-ish int | controller `+0x6EC` | players-loop alive/dead path select (`{0,3}` = alive path) |
| Icon hidden bit | `icon+0x17C` bit `0x20` | set when `m_bPawnIsAlive == 0` |
| Icon visibility flags | `icon+0x150` | `1 << type` selects the drawn sub-panel (`0xE57E20`) |
| m_iTeamNum | entity `+0x3E7` | Byte (2=CT, 3=T); confirmed on pawn AND controller |
| m_iCompTeammateColor | controller `+0x850` | Int 0–4 or unset |
| Observer services | pawn `+0x1220` | Unchanged |
| IsObserver vtable | `+0xAA0` | Unchanged |
| IsPlayerPawn vtable | `+0x4D8` | Unchanged (see `0x82C794`) |
| Observer-target handle | pawn `+0x13D0` | `-1` = not observing |

### THE switch (in-game vs demo/HLTV radar) — confirmed via SDK + RE

`mov rcx,[0x1823C8348]; mov rax,[rcx]; call [rax+0x2B0]` is
**`IVEngineClient::IsHLTV()`** (engine vtable `+0x2B0`; see
`deps/hl2sdk/public/cdll_int.h`). The radar path consumes it at ~21 sites in
`client.dll` (`0xE30xxx`–`0xE6Fxxx`); key ones:

- radar_mode `0xE3A3DB` / `0xE3A4D7` — sets show-all bit0 (together with the
  `cl_radar_show_all_players_when_spectating` cvar) when `IsHLTV() ||
  IsSpectator(local)`
- setRadarIconType `0xE55E45` — spectator/demo forces the spectator type path
  (skips live same-team competitive-type logic)
- iconColor `0xE62C33` — spectator/demo skips the live competitive RGB branch

Players-loop draw gate (`0xE4F4FB`–`0xE4F525`): teammates/self are always
drawn; enemies are drawn only when `radar+0x17760` bit0 (show-all) **or** the
`radar+0x17770` spotted/heard bit is set. Forcing `IsHLTV() -> 0` plus local
identity = the observed pawn therefore yields the exact live first-person
radar (teammates coloured, enemies only when spotted).

Prefer semantic re-resolve over these numbers after an update.

### Previous build anchors (PE `0x6A500273`, 2026-07) — historical

| Role | RVA |
| --- | --- |
| Outer radar update | `0xE25550` |
| radar_mode | `0xE1F000` |
| Players loop | `0xE328A0` |
| getLocal | `0xC10EA0` |
| getObs | `0x813F30` |
| GetEntityBySlot | `0x926920` |
| IsSpectatorCheck | `0x85B540` |
| SetRadarIconType | `0xE39320` |
| RadarIconColor | `0xE460E0` |
| GetCompColorArgb | `0x849370` |

### Pattern API (`radar_pov.cpp`)

AfxHookSource2-style hex strings (same idea as `Afx::BinUtils::FindPatternString`):

```cpp
FindPattern(base, size, "48 8B 0D ?? ?? ?? ?? FF 90 B0 02 00 00");
MatchPattern(addr, avail, "40 56 57 41 56 48 83 EC 20 ...");
FindPatternAll(base, size, pattern, maxHits);
```

- `??` = wildcard byte; spaces separate bytes.
- Prefer short structural patterns + call-chain checks over long fixed prologue masks.
- Linear scan is fine for one-shot install (module-sized); no need for SIMD scanners.

## Healthy log (success baseline)

```text
Radar POV: installed 8/8 hooks active enabled=1 update=1 getLocal=1 getObs=1 demoState=1
  getEntityBySlot=1 spectatorFilter=1 slotEnemy=1 iconType=1 forceColor=1
Radar POV: active — pawn ... -> observed ... (slot N team 2|3, spectatorSlot 0)
Radar POV: demo/HLTV state 1 -> 0 for radar frame
Radar POV: filtering demo spectator slot 0
Radar POV: GetEntityBySlot 0 -> observed slot N
Radar POV: icon-type native=17 team=2|3 selfTeam=... teammate=...   (first 3 icons)
Radar POV: icon type 0x11 -> 9|13 (teammate team 2|3, self team 2|3)
Radar POV: gate idx=185 team=2 self=2 -> 0        (teammate not gated)
Radar POV: gate idx=183 team=3 self=2 -> 1        (enemy gated → spotted-only)
Radar POV: icon idx=5 type=13 vis=0x0 f17c=0x01 f17d=0x01 alive=1 life=0
Radar POV: force-color teammate type=13 team=2 selfTeam=2 netvar=4 idx=4 argb=0xFF962CBD panels=6 playerIndex=5
```

Reading notes:

- Diagnostics are capped per session: `icon-type` ≤ 3, `gate` ≤ 3,
  `icon` state ≤ 2, `force-color` 2 samples (first + a late one); every other
  line is one-shot. A session produces ~15 radar lines total.

- `gate ... -> 0` when `team == self`, `-> 1` for the other team — that is the
  live branch; teammates must never log `-> 1`.
- `vis=0x0` at colour time is expected — the per-frame visibility updater
  (`0xE57E20`, flags `1 << type`) runs later in the same frame.
- `alive` is `m_bPawnIsAlive` (`+0x91C`), `life` is `[+0x6EC]`; `alive=0` means
  the icon is correctly hidden (dead player).

Direct-local variant (newer demo playback; `spectatorSlot -1`, pawn == observed):

```text
Radar POV: local pawn is the POV player (team 2|3) — using it directly
Radar POV: active — pawn ... -> observed ... (slot N team 2|3, spectatorSlot -1) [direct]
```

Must **not** appear:

- `team 0` on active line after POV is stable (team read failed → no colours)
- `force-color` with `team != selfTeam` (enemy leak)
- `shouldApplyCompColor` / `getCompTeammateColor` MinHook lines (removed)
- `cl_radar_show_all_players_when_spectating` from plugin QueueEngineSetup (empty)
- persistent `getLocal returned no pawn` / `no observer target yet — show-all ON`
  (POV activation failing every frame → feature inactive; check the
  direct-local fallback conditions)

## Failure matrix

| Log / visual | Action |
| --- | --- |
| `getEntityBySlot=0` | Re-resolve via icon-renderer call chain (now `FUN_18093F780`) |
| `forceColor=0` | Re-resolve iconColour (`0xE62BC0`) + `0x861BB0` |
| `active ... team 0` | Prefer pawn `+0x3E7`; fix `RefreshPovSelfTeam` |
| Allies solid team colour, no force-color lines | Hook not running or type filter excluding all |
| Enemies multi-coloured | `IsPovTeammateTeam` too loose |
| Extra freecam dot | `findPlayerBySlot` / wrong `g_spectatorSlot` |
| Teammates missing on demo radar | Check `alive`/`life` in the icon diagnostic first (dead teammates do not draw). If alive: no `gate` lines → isSlotEnemyOf arg resolution broke (must use `ResolvePlayerByIndex`); a teammate logging `gate ... -> 1` → team/selfTeam wrong |
| Install shape errors | Outer update / mode prologue masks |
| Feature completely inactive in demo | `PreparePovContext` observer chain fails AND direct-local fallback conditions not met — capture `no observer target yet` log line details |

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
