---
name: radar-pov-maintenance
description: Maintain and update the CS2 demo first-person radar (radar_pov.cpp). Use when radar POV regresses, client.dll updates break hooks/signatures, teammate competitive colours are wrong, or when revalidating the native radar path with Ghidra.
---

# CS2 Radar POV Maintenance

Maintain `cs2-server-plugin/radar_pov.cpp` so demo freecam/spectate follow uses
the same radar **feel** as live first-person: rotating map, teammate competitive
colours (not solid team orange/blue for allies), native enemy spotting, and no
freecam spectator blob.

Read **`references/current-implementation.md`** first. It is the source of truth
for the validated 7-hook design, Ghidra anchors, and healthy-log contract.

## Goal (validated contract)

| Expectation | Notes |
| --- | --- |
| Live-style layout / rotation | Identity + scoped non-demo |
| Teammates: distinct competitive colours | force ARGB via engine `cl_teammate_color_*` palette |
| Enemies: **not** competitive palette | teammate-only filter (`g_povSelfTeam`) |
| No freecam spectator icon | `findPlayerBySlot` filter |
| No forced radar cvars | `RadarPov_QueueEngineSetup` is empty |

A hook success log is **not** enough. Confirm in a demo with rotation on.

## Start with evidence

1. Work under `cs2-server-plugin`; do not discard unrelated local changes.
2. Note `client.dll` PE timestamp from log (`Radar POV: client.dll @ ... PE-timestamp=...`).
3. Read a full `csdm.log` install + first POV frame.
4. Classify before editing:

| Symptom | Likely layer |
| --- | --- |
| Install fails / missing MinHook lines | Signature / resolve |
| Empty radar or no rotation | Identity (`getLocal` / demo / update scope) |
| Solid team colours for allies | Colour path (type / force-color / self team = 0) |
| Enemies also competitive-coloured | Teammate filter broken |
| Extra freecam dot | `findPlayerBySlot` |
| Exceptions in hooks | Bad entity type or panel vtable |

## Architecture (why not one hook)

Demo and live share **one** radar update chain. Branches re-query independently:

1. **Who is local (pawn)** — `getLocal`
2. **Who is local (controller)** — `GetEntityBySlot(0)` (colour path; **not** getLocal)
3. **Is demo/HLTV** — engine vtable `+0x2B0` (scoped false during POV)
4. **Icon type** — live teammates become type `0x11`; competitive RGB in
   `FUN_180e460e0` only paints types `9` / `0xD`
5. **Actual ARGB** — demo netvars/gates often no-op; validated path **force-paints**
   after native `e460e0` using engine palette helpers

Identity rewrite alone opens the live branch but leaves type `0x11` → solid team
panels. Colour-gate-only hooks without force-paint were insufficient in demos.

**Do not reintroduce** dropped hooks unless evidence requires them:

- `IsSpectatorCheck` force-return
- presentation selector force
- `shouldApplyCompColor` / `getCompTeammateColor` (removed; force-color covers)

## Reverse engineering

Prefer Ghidra bridge when the user has it (e.g. `http://127.0.0.1:8080/`). Use
an endpoint the user provides; do not assume a fixed layout or start a second
bridge if one is running.

Rediscover by **role**, not stale absolute VA:

```text
cl_radar_show_all_players_when_spectating
  → ConVar LEA → radar_mode (FUN_180e1f000 class)
  → outer radar update wrapper (FUN_180e25550 class)
  → players loop (FUN_180e328a0)
  → set type (FUN_180e39320) / colour (FUN_180e460e0)
  → GetEntityBySlot (FUN_180926920) + IsSpectatorCheck (FUN_18085b540)
```

Useful API examples:

```sh
curl -s "http://127.0.0.1:8080/decompile_function?address=0x180e460e0"
curl -s "http://127.0.0.1:8080/decompile_function?address=0x180e39320"
curl -s "http://127.0.0.1:8080/xrefs_to?address=0x18085b540&limit=20"
```

Prefer instruction relationships + prologue masks over single brittle immediates
(e.g. `mov edi,eax` may be `8B F8` or `89 C7`).

## Implement rules

- Scope all overrides with `g_inRadarUpdate` + `g_povActive`; clear after the outer update.
- Never leave demo state forced false outside that scope.
- Validate prologues / module bounds before `MH_CreateHook`; fail closed with logs.
- Competitive colours: **teammates only** via `g_povSelfTeam` from **observed pawn**
  `m_iTeamNum` (`+0x3E7`), not only `GetEntityBySlot` (often team `0` at setup).
- `RadarPov_QueueEngineSetup` must stay empty unless product explicitly wants cvars.
- Keep changes in `radar_pov.cpp` / `.h` unless the skill docs themselves need update.

## Validate

1. Build the Windows plugin.
2. Play a competitive demo, `spec_mode` first-person, radar rotation on.
3. Check `csdm.log` against **Healthy log** in `references/current-implementation.md`.
4. Visual: allies multi-colour; enemies default (not competitive palette); no freecam dot.

## Keep this skill current

After a client update or confirmed design change, update
`references/current-implementation.md` (fingerprint, anchors, hook list, logs,
known pitfalls). Update this `SKILL.md` only when the **workflow** changes.
Mark unverified RE notes as hypotheses.
