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
