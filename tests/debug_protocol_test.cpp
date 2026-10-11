#include "../cs2-server-plugin/record_status_bridge.h"

#include <cstdlib>
#include <iostream>
#include <string>

static void Check(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

// Wire-format regression checks for the interactive debug protocol. They only
// build messages, so they run without CS2.
int main()
{
    const nlohmann::json playing = BuildDebugDemoStateMessage("dbg-1", "C:/demo/match.dem", true, false);
    Check(playing.value("name", std::string()) == "debug_demo_state", "state message must keep its name");
    const nlohmann::json& payload = playing["payload"];
    Check(payload.value("session_id", std::string()) == "dbg-1", "session id must be forwarded");
    Check(payload.value("demo_path", std::string()) == "C:/demo/match.dem", "demo path must be forwarded");
    Check(payload.value("playing", false), "playing must be reported");
    Check(!payload.value("paused", true), "a running Demo must not report a pause");
    // The desktop dropped its current-tick display, so the observation message
    // must not keep publishing a field that has no consumer.
    Check(!payload.contains("tick"), "debug_demo_state must not carry a tick field");

    const nlohmann::json paused = BuildDebugDemoStateMessage("dbg-2", "C:/demo/中文 空格.dem", true, true);
    Check(paused["payload"].value("paused", false), "engine pause must be reported");
    Check(
        paused["payload"].value("demo_path", std::string()) == "C:/demo/中文 空格.dem",
        "unicode and space paths must survive serialization");

    const nlohmann::json stopped = BuildDebugDemoStateMessage("dbg-3", "", false, false);
    Check(!stopped["payload"].value("playing", true), "unloaded playback must report stopped");
    Check(!stopped["payload"].value("paused", true), "a stopped Demo cannot be paused");

    std::cout << "debug protocol state checks passed\n";
}
