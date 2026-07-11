# Radar POV: current implementation reference

This is the project-local handoff for `radar_pov.cpp`. It describes the
currently validated implementation, not a permanent ABI contract. Revalidate
all addresses and instruction patterns after each CS2 `client.dll` update.

## Target behavior

During a demo first-person follow, the upper-left radar must look like a real
player's first-person radar:

- the map rotates with the followed player's view when radar rotation is on;
- the local player and teammates use normal in-game team presentation;
- seen enemies are native red dots, heard-but-unseen enemies can appear as the
  native red question mark, and dead enemies as the native red cross;
- the observer/spectator entry is not drawn as a fake player.

The plugin must enable this by steering native inputs. It must not emulate
radar markers or manually draw a replacement UI.

## Design that is currently validated

`radar_pov.cpp` hooks a small set of client functions. The outer radar update
creates a thread-local scope only when an observed first-person pawn exists.
Within that scope, hooks provide the observed pawn where the native code asks
for its local player, hide the demo/HLTV presentation flag, and filter the
spectator player slot. Native code then performs the usual spotted-state,
sound-question-mark, death-marker, color, and rotation work.

```text
outer radar update
  -> thread-local POV scope
  -> radar mode / player update asks for local player
       -> return observed pawn instead of spectator pawn
  -> demo/HLTV state query
       -> return false only inside the POV scope
  -> IsSpectatorCheck (icon colour gate; entity often slot-0 spectator)
       -> return false only inside the POV scope  → per-player colours
  -> player lookup by slot
       -> hide the demo spectator slot
  -> native presentation selector and renderer
       -> normal first-person rotation, colors, markers
```

The override is deliberately scoped: changing demo state globally affects
unrelated observer UI and is unsafe.

## Current reverse-engineering anchors

These are anchors from the last known-good client build. Prefer the semantic
relationships and surrounding instruction shapes over the numeric values.

| Role | Last known-good anchor | How to rediscover |
| --- | --- | --- |
| Outer radar update | RVA `0xE25550` | Locate caller that derives the radar object and invokes the mode and player-update paths. |
| Radar mode selector | RVA `0xE1F000` | Follow from outer update; it asks for local player, observer state, show-all state, then presentation selection. |
| Player update/enumeration | RVA `0xE328A0` | Follow from outer update; it resolves local player, observation state, enemy relation, and spotted data. |
| Presentation selector | RVA `0xE3EBA0` | Follow final call from radar mode; its local-POV state controls fixed versus live rotating presentation. |
| Observer target | RVA `0x813F30` | Find observer-services access; the known path used pawn observer services at `+0x1220`. |
| Demo/HLTV check | global `DAT_18239F7F8`, virtual `+0x2B0` | Trace calls in radar mode and player-class presentation; return false only during scoped POV updates. |
| Show-all/spotted field | formerly `radar + 0x17760` | Extract from the current `and byte ptr [radar + offset], ~1`-style instruction; do not hard-code it. |
| IsSpectatorCheck (colours) | RVA `0x85B540` | Icon renderer `FUN_180e460e0` calls this on `FUN_180926920(0)` (slot 0 controller, not getLocal). Both this and demo/HLTV must be false for live per-player colour classes (`controller+0x850`). Prologue: `mov [rsp+8],rbx; push rdi; sub rsp,20h; mov rbx,rcx; lea rcx,[rip]; call; cmp [rbx+0x3E7],1`. Do **not** match only `cmp [rbx+0x3E7],1` (neighbour `FUN_1808490d0` shares it). `mov edi,eax` may be `8B F8` or `89 C7`. |
| Per-player icon renderer | RVA `0xE460E0` | Called from player update; branches on IsSpectatorCheck + demo state into team-colour vs per-player colour paths. |

`ResolveRadarFunctions` intentionally uses several byte checks. They are
feature-code signatures plus structural validation: they identify code/data
relationships and prevent a changed client from hooking a guessed location.
They can change after an update, which is expected. A mismatch should disable
the feature safely and prompt re-analysis, not crash the game.

## Expected healthy log signals

The exact addresses vary. A good test log should show that the relevant hooks
resolved and installed, then show scoped transitions equivalent to:

- install line includes `isSpecCheck=1` (not `0`);
- `IsSpectatorCheck @ ... (prologue+team-cmp mask)` (or a listed fallback) appears once;
- `IsSpectatorCheck forced 0 (call #1, ...)` appears after POV becomes active;
- native demo/HLTV state changes from `1 -> 0` during the radar update;
- live-POV selector receives the local POV state expected for native rotation;
- spectator slot `0` (or the current spectator slot) is filtered;
- no hook exceptions, invalid-target messages, or game crash.

If `isSpecCheck=0`, teammates stay on team colours (T orange / CT blue) even when
rotation and spotting already look first-person — re-resolve `IsSpectatorCheck`.

Logs alone do not prove the rendering contract. Always observe a rotating
first-person demo scene containing teammates, a seen enemy, a heard enemy, and
a dead enemy.

## Update procedure after a CS2 client update

1. Preserve the last working commit and collect a fresh failing `csdm.log`.
   Record the new client timestamp and which resolver/hook first failed.
2. In Ghidra, start at the old outer-update semantic role, not its old address.
   Find its caller/callees and reconstruct the relationships listed in the
   table above.
3. Confirm each candidate with decompilation and xrefs. Distinguish a pawn from
   a controller: the local-player override must return the observed **pawn**.
4. Update signatures/extraction logic only after proving the role. Prefer a
   short, distinctive instruction relationship plus bounds checks to a large
   brittle literal byte sequence.
5. Keep hooks narrow. Do not reintroduce retired aggressive or manual-render
   fallbacks merely to make a hook install.
6. Build and test in-game. If the visual behavior is wrong while hooks work,
   trace which native input still carries spectator state rather than adding
   replacement rendering.
7. After a passing test, update this reference's anchors, fingerprint, and
   healthy-log description. Update `SKILL.md` only if the reusable workflow
   changed.

## Maintenance boundaries

- Absolute virtual addresses are build-specific; calculate targets from the
  loaded `client.dll` module and use RVAs for notes.
- Layout offsets, virtual slots, globals, and byte signatures are all subject
  to updates.
- A failed resolver is a compatibility event, not a reason to weaken
  validation.
- Keep lifecycle cleanup complete: disable installed hooks and reset all
  resolved state when installation aborts or the feature shuts down.
