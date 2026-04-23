#include "record_status_bridge.h"

#include <chrono>

namespace {
long long GetUnixTimestampMs() {
    auto now = std::chrono::system_clock::now();
    auto sinceEpoch = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return sinceEpoch.count();
}
}

bool TryParseActionMetadata(const nlohmann::json& jsonAction, ActionMetadata& outMetadata) {
    outMetadata = ActionMetadata{};
    if (!jsonAction.contains("metadata") || !jsonAction["metadata"].is_object()) {
        return false;
    }

    const auto& metadata = jsonAction["metadata"];
    outMetadata.hasMetadata = true;

    if (metadata.contains("take_index") && metadata["take_index"].is_number_integer()) {
        outMetadata.hasTakeIndex = true;
        outMetadata.takeIndex = metadata["take_index"].get<int>();
    }
    if (metadata.contains("take_name") && metadata["take_name"].is_string()) {
        outMetadata.takeName = metadata["take_name"].get<std::string>();
    }
    if (metadata.contains("record_phase") && metadata["record_phase"].is_string()) {
        outMetadata.recordPhase = metadata["record_phase"].get<std::string>();
    }
    return true;
}

bool IsMirvRecordBoundaryCommand(const std::string& cmd) {
    return cmd == "mirv_streams record start" || cmd == "mirv_streams record end";
}

nlohmann::json BuildRecordStatusMessage(
    const std::string& demoPath,
    int tick,
    const std::string& cmd,
    const ActionMetadata& metadata)
{
    nlohmann::json payload;
    payload["demo_path"] = demoPath;
    payload["tick"] = tick;
    payload["cmd"] = cmd;
    payload["ts_ms"] = GetUnixTimestampMs();

    if (metadata.hasTakeIndex) {
        payload["take_index"] = metadata.takeIndex;
    }
    if (!metadata.takeName.empty()) {
        payload["take_name"] = metadata.takeName;
    }
    if (!metadata.recordPhase.empty()) {
        payload["record_phase"] = metadata.recordPhase;
    }

    nlohmann::json msg;
    msg["name"] = "record_status";
    msg["payload"] = payload;
    return msg;
}

nlohmann::json BuildDemoStartedMessage(const std::string& demoPath) {
    nlohmann::json msg;
    msg["name"] = "demo_started";
    msg["payload"] = {
        {"demo_path", demoPath},
        {"ts_ms", GetUnixTimestampMs()},
    };
    return msg;
}

nlohmann::json BuildDemoDoneMessage(const std::string& demoPath, const std::string& reason) {
    nlohmann::json msg;
    msg["name"] = "demo_done";
    msg["payload"] = {
        {"demo_path", demoPath},
        {"reason", reason},
        {"ts_ms", GetUnixTimestampMs()},
    };
    return msg;
}
