---
name: radar-pov-maintenance
description: Maintain and update the CS2 demo first-person radar implementation in this repository. Use when radar POV visuals regress, client.dll changes after a CS2 update, radar hooks or signatures fail, or when reverse engineering and validating the native radar path with Ghidra.
---

# CS2 Radar POV Maintenance

Maintain `radar_pov.cpp` so a CS2 demo observer follows the same native radar
rendering path as a live first-person player. Read
`references/current-implementation.md` before changing code; it records the
current proven control points and the validation contract.

## Start with evidence

1. Work from `cs2-server-plugin` and preserve unrelated working-tree changes.
2. Record the current `client.dll` fingerprint (at least PE timestamp) and
   inspect a fresh `csdm.log` before changing signatures or hooks.
3. Classify the failure before editing:
   - installation/signature failure;
   - wrong local pawn or observer target;
   - spectator/demo presentation state leaking into radar;
   - stale spectator slot rendered as a player;
   - native radar still receiving the wrong mode/state.
4. Treat a hook log as proof only that the hook executed. Confirm visual
   behavior in a demo: rotation, team colors, spotted enemies, sound question
   marks, and dead-enemy crosses.

## Reverse-engineer the native path

Use the local Ghidra bridge when available:

```sh
python3 ../../ghidramcp/GhidraMCP-release-1-4/bridge_mcp_ghidra.py
curl 'http://127.0.0.1:8080/decompile_function?address=0x180e25550'
```

For the updated client, rediscover semantics rather than copying old absolute
addresses. Follow the outer radar update into the radar-mode selector, player
enumeration/update, local-player lookup, observer-target lookup, and the
presentation-state selector. Use xrefs and callers to establish what each
function does. Prefer module-relative RVAs and runtime extraction from nearby
instructions over fixed virtual addresses or field offsets.

## Implement minimally and fail closed

Keep the client renderer responsible for drawing. The plugin should only make
the radar update perceive the observed pawn as the local player and suppress
demo/spectator state while the scoped radar update runs.

- Scope thread-local overrides with RAII around the outer radar update.
- Never change global demo state outside that scope.
- Validate instruction shapes, offsets, module bounds, and hook targets before
  enabling a hook.
- If a required target cannot be resolved, leave Radar POV disabled and emit a
  precise log reason. Do not guess an address.
- Do not restore old manual marker/UI rendering unless native rendering is
  demonstrably unavailable; it cannot reproduce the full first-person radar
  contract reliably.

## Validate the result

Build the plugin, then test a representative demo with radar rotation enabled.
Inspect `csdm.log` for the resolved targets, installed hooks, scoped state
transitions, and absence of exceptions. Verify the native visual contract in
game, not only logs. Keep the change narrow and run the repository's relevant
build/check commands before publishing.

## Keep this skill current

After a confirmed game update, replace stale facts in
`references/current-implementation.md`: client fingerprint, RVAs or extraction
patterns, changed semantics, log evidence, and the visual result. Update this
`SKILL.md` only when the reusable maintenance workflow itself improved. Keep
unverified reverse-engineering hypotheses clearly marked as hypotheses.
