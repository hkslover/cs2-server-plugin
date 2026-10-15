#include "../cs2-server-plugin/debug_playback.h"

#include <cstdlib>
#include <iostream>

static void Check(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

int main()
{
    DebugPlaybackGate gate;
    gate.Begin("C:/demo/B.dem", "C:/demo/A.dem", true, 100);
    Check(!gate.Observe("C:/demo/A.dem", true, 101), "old Demo advancing must not consume settings");
    Check(!gate.Observe("C:/demo/B.dem", false, 0), "loading path without playback must not confirm");
    Check(gate.Observe("C:\\demo\\B.dem", true, 1), "new engine path must confirm the requested Demo");
    Check(!gate.Observe("C:/demo/B.dem", true, 2), "settings must only be applied once");

    gate.Begin("C:/demo/B.dem", "C:/demo/A.dem", true, 100);
    Check(gate.Observe("C:/demo/B.dem", true, 1), "path switch without a stop event must confirm");

    gate.Begin("C:/demo/B.dem", "C:/demo/B.dem", true, 100);
    Check(!gate.Observe("C:/demo/B.dem", true, 101), "replay must not consume settings on an old tick");
    Check(!gate.Observe("C:/demo/B.dem", true, 102), "continued old playback must remain pending");
    Check(gate.Observe("C:/demo/B.dem", true, 1), "replay tick rewind must confirm the reload");
    Check(!gate.Observe("C:/demo/B.dem", true, 2), "replay confirmation must only happen once");

    gate.Begin("C:/demo/B.dem", "C:/demo/B.dem", true, 0);
    Check(!gate.Observe("C:/demo/B.dem", true, 0), "paused old Demo is not a replay confirmation");
    Check(!gate.Observe("", false, -1), "stop without a Demo interface must be observed");
    Check(gate.Observe("C:/demo/B.dem", true, 0), "replay at tick zero must confirm after a stop");

    gate.Begin("C:/demo/中文 空格.dem", "", false, -1);
    Check(gate.Observe("C:/demo/中文 空格.dem", true, 0), "Unicode and spaces must survive path matching");

    gate.Begin("C:/demo/one/match.dem", "", false, -1);
    Check(!gate.Observe("C:/demo/two/match.dem", true, 0), "same basename in another directory must not match");
    Check(!gate.Observe("", true, 0), "missing engine path must not confirm playback");
    gate.Begin("C:/demo/new.dem", "", false, -1);
    Check(!gate.Observe("C:/demo/one/match.dem", true, 0), "superseded target must not consume new settings");
    Check(gate.Observe("C:/demo/new.dem", true, 0), "latest play request must win");

    // The gate has no dependency on the optional command list. Radar-only and
    // empty requests must still produce a confirmation/state event.
    gate.Begin("C:/demo/empty.dem", "C:/demo/new.dem", true, 10);
    Check(gate.Observe("C:/demo/empty.dem", true, 1), "empty draft still needs a playback confirmation");
#ifdef _WIN32
    gate.Begin("C:/DEMO/Case.dem", "", false, -1);
    Check(gate.Observe("c:\\demo\\case.dem", true, 0), "Windows matching must ignore ASCII path case");
#else
    gate.Begin("/demo/Case.dem", "", false, -1);
    Check(!gate.Observe("/demo/case.dem", true, 0), "non-Windows matching must preserve path case");
#endif
    std::cout << "debug playback confirmation regression checks passed\n";
}
