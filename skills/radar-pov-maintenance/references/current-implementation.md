# Radar POV: current implementation reference

Minimal upstream identity rewrite. Revalidate after each CS2 `client.dll` update.

## Target behavior

During demo first-person follow, the upper-left radar must match a real player's
first-person radar: rotation, teammate competitive colours, spotted enemies,
sound marks, death marks — all via native rendering.

## Design

Do **not** paint icons or rewrite icon types. Only change inputs the engine
already uses to decide live vs spectator:

```text
outer radar update (scope)
  ├─ getLocal()              → observed pawn
  ├─ GetEntityBySlot(0 / -1) → observed controller   ★ colour path local
  ├─ demo/HLTV vtable+0x2B0  → false (scoped only)
  └─ findPlayerBySlot(spec)  → nullptr (optional)
       ↓
  native live first-person path (mode, icons, colours)
```

Removed on purpose (downstream hacks):

- IsSpectatorCheck force-return
- presentation selector force
- icon type 0x11 → 9/0xD rewrite
- competitive colour gate detours
- forced ARGB SetColor on panels

## Hooks (5 max)

| Hook | Required | Role |
| --- | --- | --- |
| `radar_update` | yes | POV scope + show-all fail-safe |
| `getLocal` | yes | observed pawn as self |
| `getEntityBySlot` | yes for colours | slot 0/-1 → observed controller slot |
| `radar_demo_state` | yes | scoped non-demo |
| `findPlayerBySlot` | optional | hide freecam spectator icon |

## Healthy log

```text
Radar POV: installed (minimal upstream) ... getEntityBySlot=1 ...
Radar POV: active — pawn ... -> observed ... (slot N, spectatorSlot 0)
Radar POV: demo/HLTV state 1 -> 0 for radar frame
Radar POV: GetEntityBySlot 0 -> observed slot N
Radar POV: filtering demo spectator slot 0
```

No exceptions. Visual check still required for colours and rotation.

## Update procedure

1. Collect failing `csdm.log` + PE timestamp.
2. Re-resolve from `cl_radar_show_all_players_when_spectating` → mode → outer update.
3. Prefer semantic relationships over fixed RVAs.
4. Do not reintroduce downstream colour hacks unless identity rewrite is proven insufficient.
