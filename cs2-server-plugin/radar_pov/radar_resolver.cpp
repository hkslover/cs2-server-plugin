#include "radar_resolver.h"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

namespace RadarPovResolver {

namespace {
RadarPovLogFn g_log = nullptr;

#ifdef _WIN32
void Log(const char* fmt, ...)
{
    if (g_log == nullptr) {
        return;
    }
    char buf[1024] = {};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    g_log("%s", buf);
}
#endif
}  // namespace

void SetLogger(RadarPovLogFn logger)
{
    g_log = logger;
}

#ifdef _WIN32

using namespace MemUtils;

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

bool ResolveRadarFunctions(const ModuleInfo& client, ResolvedState& resolved)
{
    resolved = {};

    auto& g_origRadarUpdate = resolved.functions.radarUpdate;
    auto& g_origGetLocal = resolved.functions.getLocal;
    auto& g_getObserverTarget = resolved.functions.getObserverTarget;
    auto& g_getPlayerSlot = resolved.functions.getPlayerSlot;
    auto& g_origFindPlayerBySlot = resolved.functions.findPlayerBySlot;
    auto& g_origGetEntityBySlot = resolved.functions.getEntityBySlot;
    auto& g_origSetRadarIconType = resolved.functions.setRadarIconType;
    auto& g_origRadarIconColor = resolved.functions.radarIconColor;
    auto& g_getCompColorArgb = resolved.functions.getCompColorArgb;
    auto& g_resolvePlayerByIndex = resolved.functions.resolvePlayerByIndex;
    auto& g_radarDemoStateGlobalSlot = resolved.radarDemoStateGlobalSlot;
    auto& g_radarShowAllFlagOffset = resolved.radarShowAllFlagOffset;

    const uint8_t* codeBase = client.textBase != nullptr ? client.textBase : client.base;
    const size_t codeSize = client.textBase != nullptr ? client.textSize : client.size;
    if (codeBase == nullptr || codeSize == 0) {
        Log("Radar POV: executable resolver range is empty");
        return false;
    }
    Log("Radar POV: resolver code range @ %p size=0x%zx (%s)", codeBase, codeSize,
        client.textBase != nullptr ? ".text" : "client.dll fallback");

    auto rva = [&](uintptr_t address) -> size_t {
        return IsInsideModule(client, address)
            ? static_cast<size_t>(address - reinterpret_cast<uintptr_t>(client.base))
            : 0;
    };
    auto functionSize = [&](uintptr_t address) -> size_t {
        return ApproxFnSize(client, address);
    };
    auto validFunction = [&](uintptr_t address, size_t minSize = 1) -> bool {
        const size_t size = functionSize(address);
        return IsInsideText(client, address) && size >= minSize;
    };
    auto validCodeRange = [&](uintptr_t address, size_t length) -> bool {
        if (length == 0 || address > std::numeric_limits<uintptr_t>::max() - (length - 1)) {
            return false;
        }
        return IsInsideText(client, address) && IsInsideText(client, address + length - 1);
    };
    auto uniquePattern = [&](const char* label, const uint8_t* begin, size_t size,
                             const char* pattern, bool required) -> uintptr_t {
        const auto hits = FindPatternAll(begin, size, pattern, std::numeric_limits<size_t>::max());
        Log("Radar POV: resolver pattern %s candidates=%zu", label, hits.size());
        if (hits.size() != 1) {
            if (required) {
                Log("Radar POV: resolver pattern %s rejected (%s)", label,
                    hits.empty() ? "not found" : "ambiguous");
            }
            return 0;
        }
        const uintptr_t address = reinterpret_cast<uintptr_t>(hits[0]);
        Log("Radar POV: resolver pattern %s -> %p RVA=0x%zx candidates=1", label,
            reinterpret_cast<void*>(address), rva(address));
        return address;
    };

    // Function-level signatures.  These are deliberately kept separate from
    // the call-chain code so every fallback can be checked against a second
    // structural fact instead of an ordinal in a call list.
    static const char kPatGetEntityBySlot[] =
        "48 83 EC 28 83 F9 FF 75 17 48 8B 0D ?? ?? ?? ?? 48 8D 54 24 30 48 8B 01 "
        "FF 90 10 03 00 00 8B 08 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 8B 04 C1 48 83 C4 28 C3";
    static const char kPatIsSpectatorCheck[] =
        "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? "
        "80 BB E7 03 00 00 01";
    static const char kPatSetRadarIconType[] =
        "40 56 57 41 56 48 83 EC 20 8B FA 4C 8B F1 E8";
    static const char kPatGetCompColorArgb[] =
        "40 53 48 83 EC 20 48 8B D9 83 FA FF 7D";
    static const char kPatRadarIconColor[] =
        "48 85 D2 0F 84 ?? ?? ?? ?? 56 41 57 48 83 EC 58";
    static const char kPatGetPlayerSlotCall[] =
        "48 8D 54 24 24 48 8B C8 E8";
    static const char kPatFindPlayerBySlotCall[] =
        "8B CF E8 ?? ?? ?? ?? 48 89 44 24 58 48 8B D8 48 85 C0";
    static const char kPatObserverField[] = "20 12 00 00";
    static const char kPatShowAllFlag[] = "80 A3 ?? ?? ?? ?? FE";
    static const char kPatDemoState[] =
        "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 B0 02 00 00";

    auto logResolved = [&](const char* label, uintptr_t address, const char* source,
                           size_t candidates) {
        Log("Radar POV: resolved %s @ %p RVA=0x%zx source=%s candidates=%zu size=0x%zx", label,
            reinterpret_cast<void*>(address), rva(address), source, candidates,
            functionSize(address));
    };

    const char* cvarName = FindCString(client, "cl_radar_show_all_players_when_spectating");
    if (cvarName == nullptr) {
        Log("Radar POV: cvar name string not found in client.dll");
        return false;
    }
    Log("Radar POV: cvar string @ %p", cvarName);

    const auto nameXrefs = FindLeaRipXrefs(client, reinterpret_cast<uintptr_t>(cvarName));
    if (nameXrefs.empty()) {
        Log("Radar POV: no LEA xrefs to cvar name");
        return false;
    }
    Log("Radar POV: cvar name LEA xrefs=%zu", nameXrefs.size());

    struct ConvarCandidate {
        uintptr_t object = 0;
        uintptr_t registrationFn = 0;
        uintptr_t nameLea = 0;
    };
    std::vector<ConvarCandidate> convarCandidates;
    for (uintptr_t nameLea : nameXrefs) {
        const uintptr_t registrationFn = FindFunctionStart(client, nameLea);
        if (!validFunction(registrationFn)) {
            continue;
        }
        intptr_t bestDist = std::numeric_limits<intptr_t>::max();
        uintptr_t best = 0;
        size_t bestCount = 0;
        for (int delta = -0x80; delta <= 0x40; ++delta) {
            if (delta == 0) {
                continue;
            }
            const uintptr_t at = nameLea + static_cast<intptr_t>(delta);
            if (!validCodeRange(at, 7)) {
                continue;
            }
            uintptr_t target = 0;
            size_t instructionSize = 0;
            if (!DecodeLeaRip(reinterpret_cast<const uint8_t*>(at), at, target,
                              instructionSize) ||
                target == reinterpret_cast<uintptr_t>(cvarName) ||
                !IsLikelyDataObject(client, target)) {
                continue;
            }
            const intptr_t distance = delta < 0 ? -delta : delta + 0x1000;
            if (distance < bestDist) {
                bestDist = distance;
                best = target;
                bestCount = 1;
            } else if (distance == bestDist && target != best) {
                ++bestCount;
            }
        }
        Log("Radar POV: cvar LEA @ %p nearby ConVar candidates=%zu bestDistance=%s",
            reinterpret_cast<void*>(nameLea), bestCount,
            best == 0 ? "none" : "unique-distance");
        if (best != 0 && bestCount == 1) {
            bool duplicate = false;
            for (const ConvarCandidate& candidate : convarCandidates) {
                if (candidate.object == best) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                convarCandidates.push_back({best, registrationFn, nameLea});
            }
        }
    }
    Log("Radar POV: ConVar object candidates=%zu", convarCandidates.size());
    if (convarCandidates.size() != 1) {
        Log("Radar POV: ConVar object resolution rejected (%s)",
            convarCandidates.empty() ? "not found" : "ambiguous");
        return false;
    }
    const uintptr_t convarObj = convarCandidates[0].object;
    const uintptr_t regFn = convarCandidates[0].registrationFn;
    Log("Radar POV: resolved ConVar object @ %p RVA=0x%zx source=name LEA adjacency "
        "candidates=1 registration=%p",
        reinterpret_cast<void*>(convarObj), rva(convarObj), reinterpret_cast<void*>(regFn));

    const auto convarXrefs = FindLeaRipXrefs(client, convarObj);
    struct ModeCandidate {
        uintptr_t modeFn = 0;
        uintptr_t callSite = 0;
        uintptr_t callerFn = 0;
    };
    std::vector<ModeCandidate> modeCandidates;
    const auto isRadarUpdateShape = [&](uintptr_t address, uintptr_t modeFn) -> bool {
        if (!validFunction(address, 0x27) || address == modeFn) {
            return false;
        }
        const uint8_t* body = reinterpret_cast<const uint8_t*>(address);
        const size_t size = functionSize(address);
        return size >= 0x27 && MatchPattern(body, size < 0x30 ? size : 0x30, "84 D2") &&
            body[0x23] == 0x48 && body[0x24] == 0x8D && body[0x25] == 0x71 &&
            body[0x26] == 0xE0;
    };
    for (uintptr_t xref : convarXrefs) {
        const uintptr_t fn = FindFunctionStart(client, xref);
        if (!validFunction(fn) || fn == regFn) {
            continue;
        }
        const auto callSites = FindE8CallSites(client, fn);
        if (callSites.empty()) {
            continue;
        }
        const size_t size = functionSize(fn);
        const auto showAllHits = FindPatternAll(reinterpret_cast<const uint8_t*>(fn), size,
                                                kPatShowAllFlag,
                                                std::numeric_limits<size_t>::max());
        const auto demoStateHits = FindPatternAll(reinterpret_cast<const uint8_t*>(fn), size,
                                                  kPatDemoState,
                                                  std::numeric_limits<size_t>::max());
        Log("Radar POV: ConVar reader @ %p RVA=0x%zx callers=%zu showAllCandidates=%zu "
            "demoStateCandidates=%zu",
            reinterpret_cast<void*>(fn), rva(fn), callSites.size(), showAllHits.size(),
            demoStateHits.size());
        if (showAllHits.size() != 1 || demoStateHits.size() != 1) {
            continue;
        }
        for (uintptr_t callSite : callSites) {
            const uintptr_t callerFn = FindFunctionStart(client, callSite);
            if (!isRadarUpdateShape(callerFn, fn)) {
                continue;
            }
            bool duplicate = false;
            for (const ModeCandidate& candidate : modeCandidates) {
                if (candidate.modeFn == fn && candidate.callSite == callSite &&
                    candidate.callerFn == callerFn) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                modeCandidates.push_back({fn, callSite, callerFn});
            }
        }
    }
    Log("Radar POV: radar mode/caller candidates=%zu", modeCandidates.size());
    if (modeCandidates.size() != 1) {
        Log("Radar POV: radar mode resolver rejected (%s)",
            modeCandidates.empty() ? "not found" : "ambiguous");
        return false;
    }
    const uintptr_t radarModeFn = modeCandidates[0].modeFn;
    const uintptr_t modeCallSite = modeCandidates[0].callSite;
    const uintptr_t radarUpdateFn = modeCandidates[0].callerFn;
    logResolved("radar_mode", radarModeFn, "ConVar LEA -> unique reader -> update shape", 1);
    logResolved("radar_update", radarUpdateFn, "radar_mode E8 caller shape", 1);

    // and byte ptr [radar+disp32], 0FEh
    if (const uintptr_t hitAddress = uniquePattern("show-all flag",
                                                   reinterpret_cast<const uint8_t*>(radarModeFn),
                                                   functionSize(radarModeFn), kPatShowAllFlag,
                                                   true)) {
        const uint8_t* hit = reinterpret_cast<const uint8_t*>(hitAddress);
        g_radarShowAllFlagOffset =
            static_cast<ptrdiff_t>(*reinterpret_cast<const uint32_t*>(hit + 2));
    }
    if (g_radarShowAllFlagOffset <= 0) {
        Log("Radar POV: show-all flag offset not found");
        return false;
    }
    Log("Radar POV: show-all flag offset=0x%zx", static_cast<size_t>(g_radarShowAllFlagOffset));

    // mov rcx,[rip+global]; mov rax,[rcx]; call [rax+2B0h]
    if (const uintptr_t hitAddress = uniquePattern("demo/HLTV state",
                                                   reinterpret_cast<const uint8_t*>(radarModeFn),
                                                   functionSize(radarModeFn), kPatDemoState, true)) {
        const uint8_t* hit = reinterpret_cast<const uint8_t*>(hitAddress);
        const int32_t rel = *reinterpret_cast<const int32_t*>(hit + 3);
        const size_t off = static_cast<size_t>(hit - reinterpret_cast<const uint8_t*>(radarModeFn));
        const uintptr_t slot = radarModeFn + off + 7 + static_cast<intptr_t>(rel);
        if (IsInsideModule(client, slot)) {
            g_radarDemoStateGlobalSlot = slot;
        }
    }
    if (g_radarDemoStateGlobalSlot == 0) {
        Log("Radar POV: native demo/HLTV state predicate not found");
        return false;
    }
    Log("Radar POV: demo/HLTV state global @ %p",
        reinterpret_cast<void*>(g_radarDemoStateGlobalSlot));

    uintptr_t radarPlayersFn = 0;
    {
        const uintptr_t scanFrom = modeCallSite + 5;
        std::vector<uintptr_t> afterMode;
        const size_t updateSize = functionSize(radarUpdateFn);
        const uintptr_t updateEnd = radarUpdateFn + updateSize;
        if (!IsInsideText(client, scanFrom) || scanFrom >= updateEnd) {
            Log("Radar POV: radar players scan site is outside radar_update function");
            return false;
        }
        const size_t available = static_cast<size_t>(updateEnd - scanFrom);
        const size_t scanSize = available < 0x80 ? available : 0x80;
        const uint8_t* p = reinterpret_cast<const uint8_t*>(scanFrom);
        for (size_t i = 0; i + 5 <= scanSize; ++i) {
            uintptr_t target = 0;
            if (!DecodeRel32Call(p + i, scanFrom + i, target)) {
                continue;
            }
            if (!IsInsideText(client, target) || target == radarModeFn) {
                continue;
            }
            bool duplicate = false;
            for (uintptr_t candidate : afterMode) {
                if (candidate == target) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                afterMode.push_back(target);
            }
            i += 4;
        }
        std::vector<uintptr_t> playerCandidates;
        for (uintptr_t candidate : afterMode) {
            if (!validFunction(candidate)) {
                continue;
            }
            const size_t size = functionSize(candidate);
            const auto slotHits = FindPatternAll(reinterpret_cast<const uint8_t*>(candidate), size,
                                                 kPatGetPlayerSlotCall,
                                                 std::numeric_limits<size_t>::max());
            const auto findHits = FindPatternAll(reinterpret_cast<const uint8_t*>(candidate), size,
                                                 kPatFindPlayerBySlotCall,
                                                 std::numeric_limits<size_t>::max());
            Log("Radar POV: post-mode call candidate @ %p RVA=0x%zx size=0x%zx "
                "getSlotCandidates=%zu findSlotCandidates=%zu",
                reinterpret_cast<void*>(candidate), rva(candidate), size, slotHits.size(),
                findHits.size());
            if (slotHits.size() == 1 && findHits.size() == 1) {
                playerCandidates.push_back(candidate);
            }
        }
        Log("Radar POV: radar players candidates=%zu (post-mode calls=%zu)",
            playerCandidates.size(), afterMode.size());
        if (playerCandidates.size() == 1) {
            radarPlayersFn = playerCandidates[0];
            logResolved("radar_players", radarPlayersFn,
                        "radar_update post-mode call + slot/find-slot structure", 1);
        }
    }
    if (radarPlayersFn == 0) {
        Log("Radar POV: radar players function rejected (no unique structural candidate)");
        return false;
    }

    const auto playerCalls = CollectDirectCalls(client, radarPlayersFn, 0xC00);
    if (playerCalls.size() < 3) {
        Log("Radar POV: unexpected call graph in players fn (%zu calls)", playerCalls.size());
        return false;
    }

    // SetRadarIconType's first direct call is the identity helper.  Resolve
    // both ends together; do not infer getLocal from an ordinal call-list slot.
    struct IconTypeCandidate {
        uintptr_t iconTypeFn = 0;
        uintptr_t getLocalFn = 0;
    };
    std::vector<IconTypeCandidate> iconTypeCandidates;
    const auto iconTypeHits = FindPatternAll(codeBase, codeSize, kPatSetRadarIconType,
                                             std::numeric_limits<size_t>::max());
    for (const uint8_t* hit : iconTypeHits) {
        const uintptr_t iconTypeFn = reinterpret_cast<uintptr_t>(hit);
        uintptr_t getLocalFn = 0;
        if (!validFunction(iconTypeFn, 19) ||
            !DecodeRel32Call(hit + 14, iconTypeFn + 14, getLocalFn) ||
            !validFunction(getLocalFn)) {
            continue;
        }
        iconTypeCandidates.push_back({iconTypeFn, getLocalFn});
    }
    Log("Radar POV: SetRadarIconType/getLocal relationship candidates=%zu (pattern hits=%zu)",
        iconTypeCandidates.size(), iconTypeHits.size());
    if (iconTypeCandidates.size() != 1) {
        Log("Radar POV: SetRadarIconType/getLocal resolver rejected (%s)",
            iconTypeCandidates.empty() ? "not found" : "ambiguous");
        return false;
    }
    const uintptr_t setRadarIconTypeFn = iconTypeCandidates[0].iconTypeFn;
    const uintptr_t getLocalFn = iconTypeCandidates[0].getLocalFn;
    logResolved("setRadarIconType", setRadarIconTypeFn,
                "unique prologue + first-call relationship", iconTypeCandidates.size());
    logResolved("getLocal", getLocalFn, "setRadarIconType first direct call", 1);

    std::vector<uintptr_t> playerCallTargets;
    for (uintptr_t callTarget : playerCalls) {
        bool duplicate = false;
        for (uintptr_t candidate : playerCallTargets) {
            if (candidate == callTarget) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            playerCallTargets.push_back(callTarget);
        }
    }
    Log("Radar POV: radar_players direct-call target candidates=%zu (calls=%zu)",
        playerCallTargets.size(), playerCalls.size());

    std::vector<uintptr_t> observerCandidates;
    for (uintptr_t callTarget : playerCallTargets) {
        if (callTarget == getLocalFn || !validFunction(callTarget)) {
            continue;
        }
        const size_t scanSize = functionSize(callTarget) < 0x20 ? functionSize(callTarget) : 0x20;
        const auto hits = FindPatternAll(reinterpret_cast<const uint8_t*>(callTarget), scanSize,
                                         kPatObserverField,
                                         std::numeric_limits<size_t>::max());
        if (hits.size() == 1) {
            observerCandidates.push_back(callTarget);
        }
    }
    Log("Radar POV: getObserverTarget candidates=%zu (field relationship)",
        observerCandidates.size());
    if (observerCandidates.size() != 1) {
        Log("Radar POV: getObserverTarget resolver rejected (%s)",
            observerCandidates.empty() ? "not found" : "ambiguous");
        return false;
    }
    const uintptr_t getObsFn = observerCandidates[0];
    logResolved("getObs", getObsFn, "radar_players direct call + observer field", 1);

    auto resolvePlayerCall = [&](const char* label, const char* pattern,
                                 size_t callOffset) -> uintptr_t {
        const size_t bodySize = functionSize(radarPlayersFn);
        const auto hits = FindPatternAll(reinterpret_cast<const uint8_t*>(radarPlayersFn), bodySize,
                                         pattern, std::numeric_limits<size_t>::max());
        std::vector<uintptr_t> targets;
        for (const uint8_t* hit : hits) {
            uintptr_t target = 0;
            const uintptr_t callAddress = radarPlayersFn +
                static_cast<size_t>(hit - reinterpret_cast<const uint8_t*>(radarPlayersFn)) +
                callOffset;
            if (!DecodeRel32Call(hit + callOffset, callAddress, target) ||
                !validFunction(target)) {
                continue;
            }
            bool duplicate = false;
            for (uintptr_t candidate : targets) {
                if (candidate == target) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                targets.push_back(target);
            }
        }
        Log("Radar POV: %s call relationship candidates=%zu (pattern hits=%zu)", label,
            targets.size(), hits.size());
        if (targets.size() != 1) {
            Log("Radar POV: %s resolver rejected (%s)", label,
                targets.empty() ? "not found" : "ambiguous");
            return 0;
        }
        logResolved(label, targets[0], "radar_players structural call relationship", 1);
        return targets[0];
    };

    const uintptr_t getPlayerSlotFn =
        resolvePlayerCall("getPlayerSlot", kPatGetPlayerSlotCall, 8);
    const uintptr_t findPlayerBySlotFn =
        resolvePlayerCall("findPlayerBySlot", kPatFindPlayerBySlotCall, 2);
    if (getPlayerSlotFn == 0 || findPlayerBySlotFn == 0) {
        return false;
    }

    Log("Radar POV: helpers getLocal=%p getSlot=%p getObs=%p findPlayerBySlot=%p",
        reinterpret_cast<void*>(getLocalFn), reinterpret_cast<void*>(getPlayerSlotFn),
        reinterpret_cast<void*>(getObsFn), reinterpret_cast<void*>(findPlayerBySlotFn));

    // GetEntityBySlot: use the spectator-check call graph when available.  A
    // pattern-only result is accepted only when it is unique.
    {
        auto looksLikeGetEntityBySlot = [&](uintptr_t fn) -> bool {
            return validFunction(fn) &&
                MatchPattern(reinterpret_cast<const uint8_t*>(fn), functionSize(fn),
                             kPatGetEntityBySlot);
        };

        const uintptr_t isSpecFn = uniquePattern("is-spectator check", codeBase, codeSize,
                                                kPatIsSpectatorCheck, true);
        if (isSpecFn == 0) {
            return false;
        }

        std::vector<uintptr_t> callChainCandidates;
        const uintptr_t codeAddress = reinterpret_cast<uintptr_t>(codeBase);
        for (size_t i = 0; i + 5 <= codeSize; ++i) {
            if (codeBase[i] != 0xE8) {
                continue;
            }
            uintptr_t target = 0;
            if (!DecodeRel32Call(codeBase + i, codeAddress + i, target) || target != isSpecFn) {
                continue;
            }
            const size_t callOff = i;
            const size_t backStart = callOff > 0x40 ? callOff - 0x40 : 0;
            for (size_t j = backStart; j + 1 < callOff; ++j) {
                if (codeBase[j] != 0x33 || codeBase[j + 1] != 0xC9) {
                    continue;
                }
                for (size_t k = j; k + 5 <= callOff; ++k) {
                        uintptr_t getEnt = 0;
                        if (!DecodeRel32Call(codeBase + k, codeAddress + k, getEnt)) {
                            continue;
                        }
                        if (getEnt == isSpecFn || !looksLikeGetEntityBySlot(getEnt)) {
                            continue;
                        }
                        bool duplicate = false;
                        for (uintptr_t candidate : callChainCandidates) {
                            if (candidate == getEnt) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            callChainCandidates.push_back(getEnt);
                        }
                    }
            }
        }
        Log("Radar POV: GetEntityBySlot call-chain candidates=%zu", callChainCandidates.size());
        if (callChainCandidates.size() == 1) {
            g_origGetEntityBySlot =
                reinterpret_cast<GetEntityBySlotFn>(callChainCandidates[0]);
            logResolved("getEntityBySlot", callChainCandidates[0],
                        "is-spectator call chain + function pattern", 1);
        } else if (callChainCandidates.size() > 1) {
            Log("Radar POV: GetEntityBySlot resolver rejected (ambiguous call chain)");
            return false;
        } else {
            const auto hits = FindPatternAll(codeBase, codeSize, kPatGetEntityBySlot,
                                             std::numeric_limits<size_t>::max());
            Log("Radar POV: GetEntityBySlot pattern candidates=%zu", hits.size());
            if (hits.size() == 1 &&
                looksLikeGetEntityBySlot(reinterpret_cast<uintptr_t>(hits[0]))) {
                const uintptr_t target = reinterpret_cast<uintptr_t>(hits[0]);
                g_origGetEntityBySlot = reinterpret_cast<GetEntityBySlotFn>(target);
                logResolved("getEntityBySlot", target, "unique function pattern fallback", 1);
            } else if (hits.size() != 1) {
                Log("Radar POV: GetEntityBySlot resolver rejected (%s)",
                    hits.empty() ? "not found" : "ambiguous pattern");
            }
        }

        if (g_origGetEntityBySlot == nullptr) {
            Log("Radar POV: GetEntityBySlot not found");
            return false;
        }
    }

    const uintptr_t compColorFn = uniquePattern("GetCompColorArgb", codeBase, codeSize,
                                                kPatGetCompColorArgb, true);
    if (compColorFn == 0 || !validFunction(compColorFn)) {
        return false;
    }
    g_getCompColorArgb = reinterpret_cast<GetCompColorArgbFn>(compColorFn);
    logResolved("GetCompColorArgb", compColorFn, "unique function pattern", 1);

    // RadarIconColor and its player-index resolver must agree structurally.
    // The short prologue can occur in another function, so uniqueness is
    // decided only after the relationship call is checked.
    const auto radarIconColorHits = FindPatternAll(codeBase, codeSize, kPatRadarIconColor,
                                                   std::numeric_limits<size_t>::max());
    struct RadarColorCandidate {
        uintptr_t iconColorFn = 0;
        uintptr_t resolveFn = 0;
    };
    std::vector<RadarColorCandidate> radarColorCandidates;
    size_t resolveRelationshipHits = 0;
    for (const uint8_t* hit : radarIconColorHits) {
        const uintptr_t iconColorFn = reinterpret_cast<uintptr_t>(hit);
        if (!validFunction(iconColorFn)) {
            continue;
        }
        const auto resolveCallHits = FindPatternAll(
            reinterpret_cast<const uint8_t*>(iconColorFn), functionSize(iconColorFn),
            "8B 8E 58 01 00 00 E8", std::numeric_limits<size_t>::max());
        resolveRelationshipHits += resolveCallHits.size();
        for (const uint8_t* callSite : resolveCallHits) {
            uintptr_t resolveFn = 0;
            const uintptr_t callAddress = iconColorFn +
                static_cast<size_t>(callSite - reinterpret_cast<const uint8_t*>(iconColorFn)) + 6;
            if (!DecodeRel32Call(callSite + 6, callAddress, resolveFn) ||
                !validFunction(resolveFn)) {
                continue;
            }
            bool duplicate = false;
            for (const RadarColorCandidate& candidate : radarColorCandidates) {
                if (candidate.iconColorFn == iconColorFn && candidate.resolveFn == resolveFn) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                radarColorCandidates.push_back({iconColorFn, resolveFn});
            }
        }
    }
    Log("Radar POV: RadarIconColor candidates=%zu (pattern hits=%zu, relationship hits=%zu)",
        radarColorCandidates.size(), radarIconColorHits.size(), resolveRelationshipHits);
    if (radarColorCandidates.size() != 1) {
        Log("Radar POV: RadarIconColor/ResolvePlayerByIndex resolver rejected (%s)",
            radarColorCandidates.empty() ? "not found" : "ambiguous");
        return false;
    }
    const uintptr_t radarIconColorFn = radarColorCandidates[0].iconColorFn;
    g_origRadarIconColor = reinterpret_cast<RadarIconColorFn>(radarIconColorFn);
    g_resolvePlayerByIndex =
        reinterpret_cast<ResolvePlayerByIndexFn>(radarColorCandidates[0].resolveFn);
    logResolved("radarIconColor", radarIconColorFn,
                "prologue candidate + player-index call relationship", radarColorCandidates.size());
    logResolved("ResolvePlayerByIndex", radarColorCandidates[0].resolveFn,
                "radarIconColor player-index call", 1);

    g_origRadarUpdate = reinterpret_cast<RadarUpdateFn>(radarUpdateFn);
    g_origGetLocal = reinterpret_cast<GetLocalFn>(getLocalFn);
    g_getObserverTarget = reinterpret_cast<GetObserverTargetFn>(getObsFn);
    g_getPlayerSlot =
        getPlayerSlotFn != 0 ? reinterpret_cast<GetPlayerSlotFn>(getPlayerSlotFn) : nullptr;
    g_origFindPlayerBySlot = findPlayerBySlotFn != 0
        ? reinterpret_cast<FindPlayerBySlotFn>(findPlayerBySlotFn)
        : nullptr;
    g_origSetRadarIconType = reinterpret_cast<SetRadarIconTypeFn>(setRadarIconTypeFn);

    return true;
}


#endif  // _WIN32

}  // namespace RadarPovResolver
