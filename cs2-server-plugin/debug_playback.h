#pragma once

#include <string>

// Engine paths may use different separators/case on Windows. Keep the entire
// path: comparing only basenames would confuse two imported matches.
inline std::string NormalizeDebugDemoPath(std::string path)
{
    for (char& c : path) {
        if (c == '\\') c = '/';
#ifdef _WIN32
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
#endif
    }
    return path;
}

// Game-thread-only confirmation of one explicit play request. An advancing
// tick in the previous Demo is never evidence that the requested one loaded.
class DebugPlaybackGate {
public:
    void Begin(const std::string& target, const std::string& observedPath, bool playing, int tick)
    {
        targetPath = target;
        normalizedTarget = NormalizeDebugDemoPath(target);
        pending = true; // Also track requests without deferred commands.
        replay = playing && normalizedTarget == NormalizeDebugDemoPath(observedPath);
        sawStop = !playing;
        previousTick = tick;
    }

    bool Observe(const std::string& observedPath, bool playing, int tick)
    {
        if (!pending) return false;
        if (!playing) {
            sawStop = true;
            return false;
        }
        if (normalizedTarget != NormalizeDebugDemoPath(observedPath)) return false;
        // For the same file, wait for a restart rather than an ordinary tick
        // change. Compare consecutive observations so a rewind is detected
        // even when the old Demo kept advancing after the request.
        const bool rewound = tick >= 0 && previousTick >= 0 && tick < previousTick;
        previousTick = tick;
        if (replay && !sawStop && !rewound) return false;
        pending = false;
        return true;
    }

    const std::string& TargetPath() const { return targetPath; }

private:
    std::string targetPath;
    std::string normalizedTarget;
    bool pending = false;
    bool replay = false;
    bool sawStop = false;
    int previousTick = -1;
};
