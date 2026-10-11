#pragma once

#include <string>
#include <nlohmann/json.hpp>

struct ActionMetadata {
    bool hasMetadata = false;
    bool hasTakeIndex = false;
    int takeIndex = 0;
    std::string takeName;
    std::string recordPhase;
};

bool TryParseActionMetadata(const nlohmann::json& jsonAction, ActionMetadata& outMetadata);
bool IsMirvRecordBoundaryCommand(const std::string& cmd);
nlohmann::json BuildRecordStatusMessage(
    const std::string& demoPath,
    int tick,
    const std::string& cmd,
    const ActionMetadata& metadata);
nlohmann::json BuildDemoStartedMessage(const std::string& demoPath);
nlohmann::json BuildDemoDoneMessage(const std::string& demoPath, const std::string& reason);
nlohmann::json BuildSessionExitAckMessage(const std::string& requestID);

// Interactive debug protocol messages (only used when CSDM_DEBUG_SESSION is set).
nlohmann::json BuildDebugSessionReadyMessage(const std::string& sessionID, int protocolVersion);
nlohmann::json BuildDebugCommandResultMessage(
    const std::string& requestID,
    const std::string& status,
    const std::string& error);
// Playback observation for the debug workbench. `paused` is read from the
// engine on the game thread; the message deliberately carries no tick, since
// the desktop no longer displays it and never infers pause from tick growth.
nlohmann::json BuildDebugDemoStateMessage(
    const std::string& sessionID,
    const std::string& demoPath,
    bool playing,
    bool paused);
