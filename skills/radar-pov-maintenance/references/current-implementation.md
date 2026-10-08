# Radar POV: validated implementation reference

Last validated design: **8 MinHook detours**, teammate-only competitive colours,
no forced radar cvars. Revalidate after every CS2 `client.dll` update.

Validated in-game on PE `0x6AA1AE5E` (2026-09-18): demo POV shows teammates in
competitive colours, enemies only when spotted, no freecam dot.

**PE `0x6AC410BA` (2026-10-07) adaptation: every resolver step statically
revalidated offline (PASS, see "Offline static validation"), offsets updated
in `radar_pov.cpp`/resolver. Windows build + in-game demo validation still
PENDING — the healthy-log contract below is expected unchanged.

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
  ├─ IsSlotEnemyOf (players-loop call site) → live team gate (see below)
  ├─ SetRadarIconType           → teammates only: type 0x11 → 9 (T) / 0xD (CT)
  │                               + comp-allowed bit [icon+0x17D] |= 8
  └─ RadarIconColor
        native update
        then ForceCompetitiveIconColor (teammates only, engine ARGB palette)
```

### PE `0x6AC410BA` structural change: radar_mode is inlined

Since this build there is **no separate radar_mode function**: its logic
(cvar read + IsHLTV + IsSpectator + show-all clear/set) is inlined into the
outer `radar_update`. Consequences:

- `radar_update` shape is unchanged at the top (`test dl,dl` + `lea rsi,[rcx-0x20]`
  at +0x23), so the update-shape validator still works.
- The cvar is no longer LEA'd by a reader; it is read through a **global
  pointer slot adjacent to the ConVar object** (slot = object+0x8 in this
  build): `mov rax,[rip+slot]; cmp byte [rax+0x58], bpl` — cvar bool value at
  `+0x58`. The resolver finds the readers of that slot and walks back to
  `radar_update`.
- Show-all flag: `and/or byte ptr [rsi+0x17808], 0xFE / 1` (same disp32 pair)
  inside `radar_update`.
- The demo/HLTV predicate (`mov rcx,[rip+g]; mov rax,[rcx]; call [rax+0x2B0]`)
  sits inside `radar_update` too.

The direct-local fallback triggers only when the observer chain fails to
resolve a pawn AND `getLocal()` itself is a live player pawn on team T/CT.
Without it, that build silently degrades to the show-all fail-safe (native
demo radar) — i.e. the feature appears completely inactive.

### The teammate-hiding cvar (confirmed from runtime log, PE 0x6AA1AE5E; object address is per-build)

A runtime-registered ConVar ref (object `0x182339278` on PE `0x6AA1AE5E`, name
not statically extractable) reads **non-zero during demo playback**. It has three effects:

1. `IsSlotEnemyOf` (PE `0x6AA1AE5E`: 0x8B0E00; PE `0x6AC410BA`: 0x8D94E0)
   early-returns true for every non-self slot →
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
it passes the converted player index from the slot→index converter (PE
`0x6AC410BA`: `0x180ACA730`, taking (slot, &outIndex); both the native gate
and the icon-colour `ResolvePlayerByIndex` (`0x180ACADF0`) resolve through the
same low-level handle resolver (`0x1809F6B60`)). The hook must resolve with
`ResolvePlayerByIndex` exactly like the native gate does; calling
`findPlayerBySlot` on that value returns null, which silently falls back to
the native teammate-hiding path (this was the "teammates missing" bug). A
team-validated `findPlayerBySlot` fallback is kept.

### Second hiding mechanism: m_bPawnIsAlive (icon state flags)

Players loop (PE `0x6AC410BA`: `0xE4EBA780`) per icon (icon array at
`radar+0x400`, stride 0x180):

| Condition | Effect |
| --- | --- |
| `[player+0x6F4]` ∉ {0,3} | dead/dying path — position/fade only, no gate, no colour |
| `m_bPawnIsAlive` (`[controller+0x934]`) == 0 | sets icon `+0x17C` bit `0x20` (hidden), skips drawing |
| `+0x17C` bit `0x20` set while alive | clears it, skips one frame, then draws |
| otherwise | draw gate `IsSlotEnemyOf` → teammates draw, enemies spotted-gated |

`m_bPawnIsAlive` at `+0x934` was confirmed from the CCSPlayerController
schema registration table on PE `0x6AC410BA` (`mov [rsp+0x28], 0x934` next to
`lea rdx, str.m_bPawnIsAlive`, size 1; neighbours m_hPlayerPawn `+0x92C`,
m_hObserverPawn `+0x930`, m_iPawnHealth `+0x938`). The live path also checks
pawn aliveness via a pawn vtable call (`+0xAB8`). Dead teammates legitimately
do not draw (live behaviour) — check the alive state before diagnosing a
"missing teammates" report.

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
| getCompTeammateColor (8494d0) | Force path reads `+0x858` directly (PE `0x6AC410BA`) |
| QueueEngineSetup cvars | Empty; host/tool owns cvars |

## Hooks (8)

| # | Name (log) | Target role (RVA, PE `0x6AC410BA`; historical PE `0x6AA1AE5E`) | Required | Role |
| --- | --- | --- | --- | --- |
| 1 | `radar_update` | Outer update `0xEAB030` (old `0xE408D0`) (vtable `CCSGO_HudRadar` +`0x2E0`) | yes | Thread-local POV scope; show-all fail-safe |
| 2 | `getLocal` | `0xC7BB90` (old `0xC29DA0`) | yes | Observed **pawn** as self |
| 3 | `radar_demo_state` | Engine vtable `+0x2B0` (`IsHLTV`) | yes | Scoped non-demo |
| 4 | `getEntityBySlot` | `0x96AA90` (old `0x93F780`) | yes | Slot `0`/`-1` → observed controller slot |
| 5 | `findPlayerBySlot` | `0xACAA50` (old `0xA8BDC0`) (players-loop call site) | yes (product) | Hide freecam spectator slot |
| 6 | `isSlotEnemyOf` | `0x8D94E0` (old `0x8B0E00`) (players-loop call site) | yes | Live team gate; teammates always drawn |
| 7 | `setRadarIconType` | `0xEC1730` (old `0xE55E00`) | yes (current) | Teammate `0x11` → `9`/`0xD` + comp-allowed bit |
| 8 | `radarIconColor` | `0xECF030` (old `0xE62BC0`) | yes (current) | After native: force teammate ARGB |

Helpers (not hooked): `getObs` (`0x853DC0`, pawn `+0x1308`), `getPlayerSlot`
(`0x942650`), `GetCompColorArgb` (`0x889E30`), `ResolvePlayerByIndex`
(`0xACADF0`), slot→index converter (`0xACA730`), low-level handle resolver
(`0x9F6B60`), IsSpectatorCheck (`0x8D9680`), obs-target handle resolver
(`0x853D20`).

### `setRadarIconType` (what it does)

Native `FUN_180e39320(icon, playerTeam)` writes type at `icon+0x16c` and updates
panel visibility bits. Live identity makes allies type `0x11`. Competitive body
paint and the panels we SetColor (`+0x60/+0x68/+0x70` …) align with types
`9`/`0xD`. Hook runs **after** original: if POV + teammate + type `0x11`, set
`9` (T) or `0xD` (CT). Enemies unchanged.

### `radarIconColor` / force-color (what it does)

After native `FUN_180ecf030` (PE `0x6AC410BA`; old `180e460e0`): clear
rate-limit float at `icon+0x14c`; resolve
controller; require `IsPovTeammateTeam`; read `m_iCompTeammateColor` (`+0x858`),
fallback `playerIndex % 5` if unset; `GetCompColorArgb` → SetColor on panels
`0x60,0x68,0x70,0x80,0x88,0x90` (same as native competitive paint).

### Teammate filter

- `g_povSelfTeam` from **observed pawn** `+0x3E7` first (controller-via-slot often
  reads `0` at setup — that previously failed closed and blocked all colours).
- Lazy refresh in `IsPovTeammateTeam` if still invalid.
- Never competitive-colour enemies.

## Last known-good anchors (PE `0x6AC410BA`, client.dll 2026-10-07)

Resolver re-validated statically against this build (2026-10-08, offline
harness `tools/run-radar-resolver-check.sh` → PASS): every step of
`ResolveRadarFunctions` resolves uniquely. Structural offsets re-confirmed
from code + the CCSPlayerController schema table. Only code RVAs moved
versus PE `0x6AA1AE5E` — plus the changes marked **below**.

| Role | RVA (image base `0x180000000`) | Rediscovery |
| --- | --- | --- |
| Outer radar update (vtable `CCSGO_HudRadar` +`0x2E0`) | `0xEAB030` | **ConVar pointer-slot reader** (`mov r64,[rip+obj+8]`) + update shape (`84 D2` + `lea rsi,[rcx-20h]` at +0x23) + inlined mode fingerprints |
| ~~radar_mode~~ (inlined into update) | — | show-all clear/set pair `80 A6/8E disp32 FE/1` + IsHLTV call inside radar_update |
| Show-all flag | `radar+0x17808` bit0 (**was `0x17760`**) | disp32 of the and/or pair in radar_update |
| ConVar object / pointer slot | `0x2575BE8` / obj+`0x8` (slot) | cvar name string → registration LEA adjacency → object; slot = RIP targets of `mov r64,[rip+rel]` in `[obj, obj+0x20)`; cvar bool value at `+0x58` |
| demo/HLTV state global slot | `0x255D3A8` | `kPatDemoState` hit inside radar_update → RIP target |
| Players loop | `0xEBA780` | radar_update direct calls + paired slot/find-slot call-site patterns (unique) |
| Icon array | `radar+0x400`, stride `0x180` | players loop `lea rcx,[r12+0x400]; shl r14,7; lea r14,[rax+rax*2]` |
| getLocal | `0xC7BB90` | setRadarIconType first direct call (pattern unchanged) |
| getObs (observer target pawn) | `0x853DC0` | players-fn direct call + `mov rcx,[rcx+0x1308]` prologue (**was `+0x1220`**) |
| GetEntityBySlot | `0x96AA90` | full-body pattern (2 hits incl. a twin `0xCECDF0`) ∩ radarIconColor direct calls; long variant `0x96AAD0` used by getLocal |
| IsSpectatorCheck | `0x8D9680` | handle-table lookup prologue (`mov edx,[rcx+0x14bc]; cmp edx,-1`) — old prologue pattern is dead |
| IsObserver (pawn vtable) | `+0xAC0` (**was `+0xAA0`**) | `call [rax+0xAC0]` on local pawn in radar_update/players |
| IsPlayerPawn (pawn vtable) | `+0x4F0` (**was `+0x4D8`**) | `call [rax+0x4F0]` in getLocal/getObs |
| pawn-alive-ish vtable check | `+0xAB8` | `call [rax+0xAB8]` on pawn in players loop |
| obs-target handle resolver | `0x853D20` | `mov rcx,[rcx+0x1308]; jmp [vtable+0xF0]` in radar_update |
| SetRadarIconType | `0xEC1730` | prologue pattern unchanged; writes icon `+0x16c`; same-team type `0x11` (`mov ebx,0x11`, unchanged) |
| RadarIconColor | `0xECF030` | prologue pattern + `mov ecx,[rsi+0x158]; call` relationship (unchanged) |
| GetCompColorArgb | `0x889E30` | **new pattern** `4C 8B C1 83 FA FF 7D 0A C7 01 C8 C8 C8 FF` (mov r8,rcx; cmp edx,-1; jge; mov dword [rcx],0xFFC8C8C8) |
| GetCompTeammateColor (netvar read) | `0x889EE0` | radarIconColor call after ResolvePlayerByIndex; reads `m_iCompTeammateColor` at **`+0x858`** (was `+0x850`) |
| team read (with cvar override) | `0x889AE0` | `cmp byte [rcx+0x3E7],1` (m_iTeamNum **unchanged**) |
| ResolvePlayerByIndex | `0xACADF0` | radarIconColor player-index call (`icon+0x158`, unchanged) |
| getPlayerSlot | `0x942650` | players-fn `lea rdx,[rsp+0x24]; mov rcx,rax; call` (pattern unchanged) |
| findPlayerBySlot | `0xACAA50` | players-fn `mov ecx,edi; call; mov [rsp+?],rax; mov rbx,rax; test` — **stack disp wildcarded** (was `+0x58`, now `+0x60`) |
| slot→index converter | `0xACA730` | players-fn `mov edx,edi; lea rcx,[rsp+0x28]; call` (writes the gate's index) |
| IsSlotEnemyOf (draw gate) | `0x8D94E0` | players-fn `mov edx,[rsp+0x28]; mov rcx,[rsp+0x38]; call` (pattern unchanged) |
| m_bPawnIsAlive (bool) | controller `+0x934` (**was `+0x91C`**) | CCSPlayerController schema entry (m_hPlayerPawn `+0x92C`, m_hObserverPawn `+0x930`, m_iPawnHealth `+0x938`) |
| Life-state-ish int | pawn/player `+0x6F4` (**was `+0x6EC`**) | players-loop alive/dead path select (`{0,3}` = alive path) |
| Icon hidden bit | icon `+0x17C` bit `0x20` | unchanged (set when pawn not alive) |
| Icon visibility flags | icon `+0x150` | unchanged (`1 << type` per-frame updater) |
| m_iTeamNum | entity `+0x3E7` | unchanged (byte 2=CT, 3=T; pawn AND controller) |
| m_iCompTeammateColor | controller `+0x858` (**was `+0x850`**) | schema + GetCompTeammateColor read |
| Observer services | pawn `+0x1308` (**was `+0x1220`**) | getObs prologue; internal vtable `+0x100` unchanged |
| Engine vtable IsHLTV | `+0x2B0` | unchanged (`kPatDemoState`) |
| Engine vtable slot-query | `+0x310` | GetEntityBySlot slot -1 path (`FF 90 10 03 00 00`, unchanged) |
| Observer-target handle | services vtable `+0xF0` → handle `[resolved+0x4C]` | radar_update obs-target path (`0x853D20`; replaces pawn `+0x13D0`) |
| Icon type / playerIndex / colorTime / comp-allowed | `+0x16C` / `+0x158` / `+0x14C` / `+0x17D` | all unchanged |
| Panel get-style / style SetColor vtables | `+0x230` / `+0x188` | unchanged; panels `0x60,0x68,0x70` (T) / `0x80,0x88,0x90` (CT) unchanged |

### Previous build anchors (PE `0x6AA1AE5E`, 2026-09) — historical

| Role | RVA / offset |
| --- | --- |
| Outer radar update | `0xE408D0` |
| radar_mode (separate fn then) | `0xE3A380` |
| Show-all flag / spotted bitmask | `radar+0x17760` / `radar+0x17770` |
| Players loop | `0xE4EF90` |
| getLocal / getObs | `0xC29DA0` / `0x82C770` |
| GetEntityBySlot / IsSpectatorCheck | `0x93F780` / `0x873D80` |
| IsSpectator(pawn) `+0x13D0` handle | `0x8B0F00` |
| SetRadarIconType / RadarIconColor | `0xE55E00` / `0xE62BC0` |
| GetCompColorArgb / GetCompTeammateColor | `0x861BB0` / `0x861D10` |
| ResolvePlayerByIndex / getPlayerSlot / findPlayerBySlot | `0xA8C160` / `0x918130` / `0xA8BDC0` |
| IsSlotEnemyOf | `0x8B0E00` |
| IsObserver / IsPlayerPawn vtable | `+0xAA0` / `+0x4D8` |
| Observer services | pawn `+0x1220` |
| m_bPawnIsAlive / life-state int | `+0x91C` / `+0x6EC` |
| m_iCompTeammateColor | `+0x850` |

### THE switch (in-game vs demo/HLTV radar) — confirmed via SDK + RE

`mov rcx,[rip+g]; mov rax,[rcx]; call [rax+0x2B0]` is
**`IVEngineClient::IsHLTV()`** (engine vtable `+0x2B0`; see
`deps/hl2sdk/public/cdll_int.h`). On PE `0x6AC410BA` the radar path consumes it
at ~29 sites; key ones:

- radar_update inlined mode logic (PE `0x6AC410BA`: `0xEAB0C3`; old
  radar_mode `0xE3A3DB`/`0xE3A4D7`) — sets show-all bit0 (together with the
  `cl_radar_show_all_players_when_spectating` cvar read via the pointer
  slot) when `IsHLTV() || IsSpectator(local)`
- setRadarIconType `0xEC176B` (old `0xE55E45`) — spectator/demo forces the
  spectator type path (skips live same-team competitive-type logic)
- iconColor `0xECF05?` (old `0xE62C33`) — spectator/demo skips the live
  competitive RGB branch

Players-loop draw gate (PE `0x6AC410BA`: `0xEBAAC0`; old `0xE4F4FB`–`0xE4F525`):
teammates/self are always drawn; enemies are drawn only when the show-all
bit (radar `+0x17808` bit0 now) **or** the spotted/heard bit is set. Forcing
`IsHLTV() -> 0` plus local identity = the observed pawn therefore yields the
exact live first-person radar (teammates coloured, enemies only when
spotted).

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

### Pattern API (`radar_pov/radar_resolver.cpp`)

AfxHookSource2-style hex strings (same idea as `Afx::BinUtils::FindPatternString`):

```cpp
FindPattern(base, size, "48 8B 0D ?? ?? ?? ?? FF 90 B0 02 00 00");
MatchPattern(addr, avail, "40 56 57 41 56 48 83 EC 20 ...");
FindPatternAll(base, size, pattern, maxHits);
```

- `??` = wildcard byte; spaces separate bytes.
- Prefer short structural patterns + call-chain checks over long fixed prologue masks.
- Linear scan is fine for one-shot install (module-sized); no need for SIMD scanners.
- `CollectDirectCalls` skips 5 bytes only when a decoded E8 target lands inside
  the module (fixed 2026-10-08): a trailing E8 byte inside another instruction
  (e.g. `mov ebp,eax` = `8B E8`) used to desync the scan and silently miss the
  real call that followed (found via `GetEntityBySlot` twin disambiguation).

## Offline static validation (no Windows box / Ghidra needed)

`tools/run-radar-resolver-check.sh [client.dll]` maps a `client.dll` PE file
image (sections at their VirtualAddresses) and re-runs the production
`RadarPovResolver::ResolveRadarFunctions` unchanged (guard macro
`RADAR_POV_RESOLVER_STATIC_TEST`), printing every step + the final
resolved-RVA table. Run it FIRST after every CS2 update:

- **PASS** → resolver chains are intact for the new build; only check the
  hardcoded `radar_pov.cpp` offsets against the anchor table above
  (schema-string verification below).
- **FAIL** → the log pinpoints the broken chain; investigate with
  `tools/radar_dll_analysis.py` (PE mapping + capstone disassembler:
  `--calls <rva>` lists direct call targets, `<rva> [len]` disassembles).

Hardcoded `radar_pov.cpp` offsets can be re-verified statically from the
schema registration table: find the netvar name string (e.g.
`m_bPawnIsAlive`, `m_iCompTeammateColor`, `m_iTeamNum`) in the image, find its
`lea rdx,[str]` in the CCSPlayerController schema builder, and read the
`mov dword [rsp+0x28], <offset>` written immediately before it
(`mov dword [rsp+0x20], <size>` follows).

## Healthy log (success baseline)

Baseline captured on PE `0x6AA1AE5E`. The same contract is expected on PE
`0x6AC410BA` (statically revalidated; in-game confirmation pending — replace
this note with the captured log lines after the demo test).

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
  (flags `1 << type`) runs later in the same frame.
- `alive` is `m_bPawnIsAlive` (`+0x934` on PE `0x6AC410BA`; `+0x91C` on
  `0x6AA1AE5E`), `life` is `[+0x6F4]` (was `[+0x6EC]`); `alive=0` means
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
| Static check `cvar name string not found` | Harness PE mapping bug or cvar renamed — check `dll/client.dll` first |
| Static check FAIL at `radar_update candidates` | ConVar pointer-slot reader chain broke — see "PE `0x6AC410BA` structural change" |
| Static check FAIL at `GetEntityBySlot ... ambiguous` | Twin pattern hit without a unique radarIconColor call — check `CollectDirectCalls` desync |
| `getEntityBySlot=0` | Re-resolve via icon-renderer call chain (PE `0x6AC410BA`: `0x96AA90` via radarIconColor call graph) |
| `forceColor=0` | Re-resolve iconColour (`0xECF030`) + `GetCompColorArgb` (`0x889E30`) |
| `active ... team 0` | Prefer pawn `+0x3E7`; fix `RefreshPovSelfTeam` |
| Allies solid team colour, no force-color lines | Hook not running or type filter excluding all |
| Enemies multi-coloured | `IsPovTeammateTeam` too loose |
| Extra freecam dot | `findPlayerBySlot` / wrong `g_spectatorSlot` |
| Teammates missing on demo radar | Check `alive`/`life` in the icon diagnostic first (dead teammates do not draw). If alive: no `gate` lines → isSlotEnemyOf arg resolution broke (must use `ResolvePlayerByIndex`); a teammate logging `gate ... -> 1` → team/selfTeam wrong |
| Install shape errors | Outer update shape (`84 D2` + `lea rsi,[rcx-20h]` at +0x23) or inlined-mode fingerprints |
| Feature completely inactive in demo | `PreparePovContext` observer chain fails AND direct-local fallback conditions not met — capture `no observer target yet` log line details |

## Update procedure after CS2 patch

1. Keep last good commit; put the new `client.dll` in `dll/` and capture its PE
   timestamp (the offline harness prints it).
2. Run `tools/run-radar-resolver-check.sh` — PASS means the resolver survives
   the update unchanged; FAIL pinpoints the broken chain.
3. For FAIL chains (or to verify hardcoded `radar_pov.cpp` offsets): use
   `tools/radar_dll_analysis.py` / Ghidra to re-find the structure by role
   (update shape, players loop, icon type/colour, schema strings) and update
   only the broken resolvers/patterns; keep the hook set unless proven
   reducible.
4. Build (Windows / `Build Windows CS2 Plugin` workflow), demo test, then
   update this file's anchors + healthy log with the captured runtime lines.
5. Do not force cvars in `QueueEngineSetup` unless product requires it.

## Product notes

- Default enabled on `ClientFullyConnect` when install succeeds.
- Console: `csdm_radar_pov 0|1`.
- Single-hook solution is **not** available with current engine structure (multiple independent local/demo queries + type/colour split).
