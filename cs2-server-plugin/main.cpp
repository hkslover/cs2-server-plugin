#include <atomic>
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <deque>
#include <thread>
#include <fstream>
#include <mutex>
#include <queue>
#include <sstream>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>
#include <nlohmann/json.hpp>
#include <easywsclient.hpp>
#include "icvar.h"
#include "cs2_cvar_access.h"
#include "cdll_interfaces.h"
#include "debug_playback.h"
#include "record_status_bridge.h"
#include "radar_pov.h"
#ifdef _WIN32
#define SERVER_LIB_PATH "\\csgo\\bin\\win64\\server.dll"
#else
#include <dlfcn.h>
#include <sys/mman.h>
#define SERVER_LIB_PATH "/csgo/bin/linuxsteamrt64/libserver.so"
#define PAGESIZE 4096
#endif

// IDKW registering a cmd on Linux makes the game process exit with a non zero code (Segmentation fault)
#ifdef _WIN32
#define CON_COMMAND_ENABLED 1
#endif

using easywsclient::WebSocket;
using nlohmann::json;
using std::string;

void* GetLibAddress(void* lib, const char* name) {
#if defined _WIN32
    return GetProcAddress((HMODULE)lib, name);
#else
    return dlsym(lib, name);
#endif
}

char* GetLastErrorString() {
#ifdef _WIN32
    DWORD error = GetLastError();
    static char s[_MAX_U64TOSTR_BASE2_COUNT];
    sprintf(s, "%lu", error);

    return s;
#else
    return dlerror();
#endif
}

void* LoadLib(const char* path) {
#ifdef _WIN32
    return LoadLibrary(path);
#else
    return dlopen(path, RTLD_NOW);
#endif
}

struct Action {
    int tick;
    string cmd;
    ActionMetadata metadata;
};

struct Sequence {
    std::vector<Action> actions;
};

typedef bool (*AppSystemConnectFn)(IAppSystem* appSystem, CreateInterfaceFn factory);
typedef void (*AppSystemShutdownFn)();
typedef void (*FrameStageNotifyFn)(void* thisptr, ClientFrameStage_t curStage);
typedef void (*ClientFullyConnectFn)(void* thisptr, int playerSlot);

CreateInterfaceFn factory = NULL;
AppSystemConnectFn serverConfigConnect = NULL;
ClientFullyConnectFn originalClientFullyConnect = NULL;
AppSystemShutdownFn serverConfigShutdown = NULL;
CreateInterfaceFn serverCreateInterface = NULL;
ISource2EngineToClient* engineToClient = NULL;
ISource2Client* client = NULL;
FrameStageNotifyFn originalFrameStageNotify = NULL;
ICvar* g_pCVar = NULL;
std::thread* wsConnectionThread = NULL;
std::thread* debugBootstrapThread = NULL;
string gameInfoPath;
string gameInfoBackupPath;
const char* demoPath = NULL;
std::string activeDemoPath;
bool isPlayingDemo = false;
std::atomic<int> currentTick{-1};
std::atomic<bool> isQuitting{false};
bool shouldDeleteLogFile = true;
std::mutex logMutex;
std::string logFilePath;
bool logFilePathInitialized = false;
std::mutex sequencesMutex;
std::queue<Sequence> sequences;

// One unit of work for the game thread. Ordinary console commands keep using
// the string wrapper, while an interactive debug request carries its own
// request id and the full ordered command list so the game thread can answer
// only after every command was processed.
struct PendingEngineCommand {
    std::string cmd;
    bool debugBatch = false;
    std::string debugRequestID;
    std::vector<std::string> debugCommands;
    // debug_play_demo is a debug-only unit: clear any queued sequences, load
    // the Demo, and apply deferred draft commands after target playback is
    // confirmed. It never touches the Demo's produce sequence file.
    bool debugPlayDemo = false;
    std::string debugPlayDemoPath;
    std::vector<std::string> debugPlayDemoCommands;
};
std::mutex pendingCommandsMutex;
std::queue<PendingEngineCommand> pendingCommands;
std::atomic<bool> wsConnected{false};
std::atomic<bool> exitAfterWebSocketAck{false};

// Interactive debug protocol gate. Empty unless the host launched this game
// with CSDM_DEBUG_SESSION, which keeps formal production behavior unchanged.
std::string debugSessionID;
const int DEBUG_PROTOCOL_VERSION = 1;
// Deferred debug playback commands (the debug-draft game settings) applied once
// on the game thread when the requested Demo's playback is confirmed. Plugin special
// actions are initialized when the play request is handled, so only ordinary
// Demo-dependent commands stay here. All access is on the game thread.
DebugPlaybackGate debugPlaybackGate;
std::vector<std::string> debugPendingPlaybackCommands;
// Published by the game thread only after the frame hook can resolve the engine
// and consume commands. Interface lookup alone is not proof of a live consumer.
std::atomic<bool> engineCommandReady{false};
// Guards one-time installation of the FrameStageNotify hook and the
// ClientFullyConnect initialization.
std::mutex clientHookMutex;
std::atomic<bool> clientFullyConnectInitialized{false};

struct OutboundWebSocketMessage {
    std::string payload;
    std::string name;
    bool durable;
    int priority;
};

const size_t MAX_OUTBOUND_WEBSOCKET_MESSAGES = 512;
const size_t MAX_DURABLE_WEBSOCKET_MESSAGES = 128;
std::mutex outboundWebSocketMessagesMutex;
std::deque<OutboundWebSocketMessage> outboundWebSocketMessages;
std::deque<OutboundWebSocketMessage> durableWebSocketMessages;
std::atomic<unsigned long> droppedWebSocketMessages{0};
std::atomic<bool> captureInProgress{false};
std::chrono::steady_clock::time_point captureStartTime;
std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();

std::string ResolveLogFilePath()
{
    const char* configuredPath = getenv("CSDM_LOG_PATH");
    if (configuredPath != NULL && configuredPath[0] != '\0') {
        return std::string(configuredPath);
    }
    return "csdm.log";
}

void EnsureLogFilePath()
{
    std::lock_guard<std::mutex> lock(logMutex);
    if (!logFilePathInitialized) {
        logFilePath = ResolveLogFilePath();
        logFilePathInitialized = true;
    }
}

void LogToFile(const char* pMsg) {
    EnsureLogFilePath();
    std::lock_guard<std::mutex> lock(logMutex);
    FILE* pFile = fopen(logFilePath.c_str(), "a");
    if (pFile == NULL && logFilePath != "csdm.log")
    {
        // A configured host-managed path may disappear or be inaccessible.
        // Preserve standalone-plugin behavior by falling back to the legacy
        // relative log file instead of silently losing all file diagnostics.
        logFilePath = "csdm.log";
        pFile = fopen(logFilePath.c_str(), "a");
    }
    if (pFile == NULL)
    {
        return;
    }

    fprintf(pFile, "%s\n", pMsg);
    fclose(pFile);
}

void DeleteLogFile()
{
    EnsureLogFilePath();
    std::lock_guard<std::mutex> lock(logMutex);
    remove(logFilePath.c_str());
}

void Log(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    char buf[1024] = {};
    vsnprintf(buf, sizeof(buf), msg, args);
    ConColorMsg(Color(227, 0, 255, 255), "CSDM: %s\n", buf);
    va_end(args);
    LogToFile(buf);
}

void PluginError(const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    char buf[1024] = {};
    vsnprintf(buf, sizeof(buf), msg, args);
    va_end(args);

    // Since the "Armory" update, calling Plat_FatalErrorFunc crashes the game on Windows.
#ifdef _WIN32
    Plat_MessageBox("Error", buf);
    Plat_ExitProcess(1);
#else
    Plat_FatalErrorFunc("%s", buf);
#endif
}

inline bool FileExists(const std::string& name) {
    std::ifstream f(name.c_str());

    return f.good();
}

static void UnhideCommandsAndCvars()
{
    if (g_pCVar == NULL) {
        Log("VEngineCvar007 interface not found; skipping command/CVar unhide");
        return;
    }

    // See cs2_cvar_access.h. CS2's legacy ConCommandRef / ConVarRef wrappers
    // are no longer safe after the July 2026 update, so enumerate through the
    // current VEngineCvar007 API instead (the same approach as advancedfx).
    auto cvar = reinterpret_cast<CS2CvarAccess*>(g_pCVar);
    const std::int64_t flagsToRemove = FCVAR_HIDDEN | FCVAR_DEVELOPMENTONLY;
    std::size_t commandsUnhidden = 0;
    std::size_t cvarsUnhidden = 0;
    std::size_t commandCount = 0;
    std::size_t cvarCount = 0;

    for (std::size_t index = 0; index < CS2_MAX_VALID_CVAR_COUNT; ++index) {
        CS2CommandEntry* command = cvar->GetCmd(index);
        if (command == NULL || command->flags == 0x400) {
            break;
        }
        ++commandCount;
        if (command->flags & flagsToRemove) {
            command->flags &= ~flagsToRemove;
            ++commandsUnhidden;
        }
    }

    for (std::size_t index = 0; index < CS2_MAX_VALID_CVAR_COUNT; ++index) {
        CS2CvarEntry* entry = cvar->GetCvar(index);
        if (entry == NULL) {
            break;
        }
        ++cvarCount;
        if (entry->flags & flagsToRemove) {
            entry->flags &= ~flagsToRemove;
            ++cvarsUnhidden;
        }
    }

    Log("CVar unhide complete: commands %zu (%zu changed), cvars %zu (%zu changed)", commandCount, commandsUnhidden, cvarCount, cvarsUnhidden);
}

void PatchVTableEntry(void** vtable, int index, void* newFunc) {
    size_t protectSize = sizeof(void*) * (index + 1);
#ifdef _WIN32
    DWORD oldProtect = 0;
    if (!VirtualProtect(vtable, protectSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        PluginError("VirtualProtect PAGE_EXECUTE_READWRITE failed: %d", GetLastError());
    }
    vtable[index] = newFunc;
    DWORD ignore = 0;
    if (!VirtualProtect(vtable, protectSize, oldProtect, &ignore))
    {
        PluginError("VirtualProtect restore failed: %d", GetLastError());
    }
#else
    void* slotAddr = (void*)&vtable[index];                                                                      
    void* pageStart = (void*)((uintptr_t)slotAddr & ~(PAGESIZE - 1)); 
    if (mprotect(pageStart, PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
    {
        PluginError("mprotect failed: %s", strerror(errno));
    }
    vtable[index] = newFunc;
    if (mprotect(pageStart, PAGESIZE, PROT_READ | PROT_EXEC) != 0)
    {
        PluginError("mprotect restore failed: %s", strerror(errno));
    }
#endif
}

void QueueEngineCommand(const std::string& cmd) {
    std::lock_guard<std::mutex> lock(pendingCommandsMutex);
    PendingEngineCommand item;
    item.cmd = cmd;
    pendingCommands.push(item);
}

// Enqueue one interactive debug request. The whole command list is processed on
// the game thread and answered once; the WebSocket thread never calls the
// engine and never acknowledges before execution.
void QueueDebugCommands(const std::string& requestID, std::vector<std::string> commands) {
    std::lock_guard<std::mutex> lock(pendingCommandsMutex);
    PendingEngineCommand item;
    item.debugBatch = true;
    item.debugRequestID = requestID;
    item.debugCommands = std::move(commands);
    pendingCommands.push(std::move(item));
}

// Enqueue one interactive debug playback request. The game thread clears any
// queued sequences, loads the Demo and answers once; the WebSocket thread never
// calls the engine and never acknowledges before execution.
void QueueDebugPlayDemo(const std::string& requestID, const std::string& demoPath, std::vector<std::string> commands) {
    std::lock_guard<std::mutex> lock(pendingCommandsMutex);
    PendingEngineCommand item;
    item.debugPlayDemo = true;
    item.debugRequestID = requestID;
    item.debugPlayDemoPath = demoPath;
    item.debugPlayDemoCommands = std::move(commands);
    pendingCommands.push(std::move(item));
}

static void QueueEngineCommandCStr(const char* cmd) {
    if (cmd != NULL) {
        QueueEngineCommand(std::string(cmd));
    }
}

static std::string TrimWhitespace(const std::string& value) {
    const char* whitespace = " \t\r\n";
    std::size_t start = value.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return std::string();
    }
    std::size_t end = value.find_last_not_of(whitespace);
    return value.substr(start, end - start + 1);
}

// Shared entry for plugin special actions. The automatic JSON sequence path and
// queued debug commands both call it, and anything it does not handle is sent
// to the engine as-is. `csdm_radar_pov` is not a registered cvar, so it must be
// intercepted here rather than forwarded to ExecuteClientCmd.
//
// Returns true when cmd is a plugin special command (handled or failed) and
// must not go to the engine. On failure outError is non-empty.
static bool TryHandlePluginSpecialCommand(const std::string& cmd, std::string& outError)
{
    outError.clear();
    static const char kRadarPovCmd[] = "csdm_radar_pov";
    static const char kRadarPovCmdPref[] = "csdm_radar_pov ";  // includes trailing space
    if (cmd != kRadarPovCmd && cmd.rfind(kRadarPovCmdPref, 0) != 0) {
        return false;
    }

    // A combined string is handed to the engine as a whole. Special actions are
    // not console commands, so they must be sent on their own; swallowing the
    // rest of a semicolon chain here would silently drop commands.
    if (cmd.find(';') != std::string::npos) {
        return false;
    }

    // Optional arg: only 0 / false / off disable; anything else (or bare cmd) enables.
    bool wantEnable = true;
    if (cmd.rfind(kRadarPovCmdPref, 0) == 0) {
        const string arg = cmd.substr(sizeof(kRadarPovCmdPref) - 1);
        if (arg == "0" || arg == "false" || arg == "off" || arg == "no") {
            wantEnable = false;
        }
    }

    if (!wantEnable) {
        if (!RadarPov_IsEnabled()) {
            Log("Radar POV: already disabled, ignoring command");
            return true;
        }
        RadarPov_SetEnabled(false);
        Log("Radar POV: disabled (hooks left installed; set csdm_radar_pov to re-enable)");
        return true;
    }

    if (RadarPov_IsInstalled() && RadarPov_IsEnabled()) {
        Log("Radar POV: already active, ignoring duplicate command");
        return true;
    }

    RadarPov_SetLogger(&Log);
    RadarPov_SetEnabled(true);

    if (RadarPov_IsInstalled()) {
        Log("Radar POV: hooks already installed, re-enabled");
        return true;
    }

    if (RadarPov_Install()) {
        RadarPov_QueueEngineSetup(&QueueEngineCommandCStr);
        Log("Radar POV ready (installed=%d enabled=%d)",
            RadarPov_IsInstalled() ? 1 : 0, RadarPov_IsEnabled() ? 1 : 0);
        return true;
    }

    outError = "Radar POV hook installation failed";
    Log("Radar POV: install failed");
    return true;
}

void SendMsg(const json& msg);

// Apply the deferred debug playback commands once, on the game thread, at the
// moment the Demo can actually accept them. Plugin special actions were already
// initialized when the play request was handled. The caller must first confirm
// that the engine is playing the requested Demo through debugPlaybackGate.
static void ApplyDebugPlaybackCommands(ISource2EngineToClient* engine)
{
    std::vector<std::string> commands = std::move(debugPendingPlaybackCommands);
    debugPendingPlaybackCommands.clear();
    for (auto& rawCmd : commands) {
        const std::string cmd = TrimWhitespace(rawCmd);
        if (cmd.empty()) {
            continue;
        }
        std::string specialError;
        if (TryHandlePluginSpecialCommand(cmd, specialError)) {
            Log("Handled deferred debug playback special command: %s", cmd.c_str());
            continue;
        }
        Log("Applying deferred debug playback command: %s", cmd.c_str());
        engine->ExecuteClientCmd(0, cmd.c_str(), true);
    }
}

// Handle one debug_play_demo request on the game thread. It clears any queued
// sequences (debug playback never runs a produce plan), initializes plugin
// special actions immediately, defers ordinary draft commands until playback
// actually starts, and issues a quoted playdemo.
static void HandleDebugPlayDemoOnGameThread(ISource2EngineToClient* engine, PendingEngineCommand& item)
{
    {
        std::lock_guard<std::mutex> lock(sequencesMutex);
        sequences = {};
    }
    const char* observedPath = engine->GetDemoFilePath();
    auto demo = engine->GetDemoFile();
    debugPlaybackGate.Begin(item.debugPlayDemoPath,
        observedPath ? observedPath : "", engine->IsPlayingDemo(),
        demo ? demo->GetDemoTick() : -1);

    std::vector<std::string> deferred;
    std::string firstError;
    for (auto& rawCmd : item.debugPlayDemoCommands) {
        const std::string cmd = TrimWhitespace(rawCmd);
        if (cmd.empty()) {
            continue;
        }
        std::string specialError;
        if (TryHandlePluginSpecialCommand(cmd, specialError)) {
            Log("Handled debug playback special command: %s", cmd.c_str());
            if (!specialError.empty() && firstError.empty()) {
                firstError = specialError;
            }
            continue;
        }
        deferred.push_back(cmd);
    }
    debugPendingPlaybackCommands = std::move(deferred);

    const std::string playCmd = "playdemo \"" + item.debugPlayDemoPath + "\"";
    Log("Debug playback: %s", playCmd.c_str());
    engine->ExecuteClientCmd(0, playCmd.c_str(), true);

    SendMsg(BuildDebugCommandResultMessage(
        item.debugRequestID,
        firstError.empty() ? "executed" : "failed",
        firstError));
}

ISource2EngineToClient* GetEngine()
{
    if (engineToClient != NULL) {
        return engineToClient;
    }

    if (factory == NULL) {
        return NULL;
    }

    engineToClient = (ISource2EngineToClient*)factory("Source2EngineToClient001", NULL);

    return engineToClient;
}

bool IsDurableWebSocketMessage(const std::string& name)
{
    return name == "record_status" || name == "demo_started" || name == "demo_done" ||
        name == "debug_demo_state";
}

int GetWebSocketMessagePriority(const std::string& name)
{
    if (name == "demo_done" || name == "session_exit_ack" ||
        name == "debug_session_ready" || name == "debug_command_result" ||
        name == "debug_demo_state") {
        return 2;
    }
    if (name == "record_status" || name == "demo_started") {
        return 1;
    }
    return 0;
}

bool RemoveLowerPriorityMessageLocked(int priority)
{
    for (auto it = outboundWebSocketMessages.begin(); it != outboundWebSocketMessages.end(); ++it) {
        if (it->priority < priority) {
            outboundWebSocketMessages.erase(it);
            return true;
        }
    }
    return false;
}

void EnqueueWebSocketMessage(OutboundWebSocketMessage message)
{
    bool dropped = false;
    {
        std::lock_guard<std::mutex> lock(outboundWebSocketMessagesMutex);
        if (outboundWebSocketMessages.size() >= MAX_OUTBOUND_WEBSOCKET_MESSAGES) {
            if (!RemoveLowerPriorityMessageLocked(message.priority)) {
                dropped = true;
            }
        }
        if (!dropped) {
            outboundWebSocketMessages.push_back(message);
        }
    }
    if (dropped) {
        unsigned long dropCount = ++droppedWebSocketMessages;
        Log("Dropping outbound WebSocket message name=%s priority=%d drop_count=%lu", message.name.c_str(), message.priority, dropCount);
    }
}

void SendMsg(const json& msg) {
    try {
        std::string name = msg.value("name", std::string());
        if (name.empty()) {
            Log("Cannot queue WebSocket message without name");
            return;
        }
        OutboundWebSocketMessage outbound;
        outbound.payload = msg.dump();
        outbound.name = name;
        outbound.durable = IsDurableWebSocketMessage(name);
        outbound.priority = GetWebSocketMessagePriority(name);
        EnqueueWebSocketMessage(outbound);
    }
    catch (const std::exception& error) {
        Log("Cannot serialize outbound WebSocket message: %s", error.what());
    }
}

void RememberDurableWebSocketMessage(const OutboundWebSocketMessage& message)
{
    if (!message.durable) {
        return;
    }
    std::lock_guard<std::mutex> lock(outboundWebSocketMessagesMutex);
    durableWebSocketMessages.push_back(message);
    while (durableWebSocketMessages.size() > MAX_DURABLE_WEBSOCKET_MESSAGES) {
        durableWebSocketMessages.pop_front();
    }
}

void ReplayDurableWebSocketMessages(WebSocket::pointer socket)
{
    std::vector<OutboundWebSocketMessage> replay;
    {
        std::lock_guard<std::mutex> lock(outboundWebSocketMessagesMutex);
        replay.assign(durableWebSocketMessages.begin(), durableWebSocketMessages.end());
    }
    for (const auto& message : replay) {
        if (socket->getReadyState() != WebSocket::OPEN || isQuitting) {
            return;
        }
        socket->send(message.payload);
    }
    if (!replay.empty()) {
        Log("Replayed %zu durable WebSocket events after reconnect", replay.size());
    }
}

void DrainOutboundWebSocketMessages(WebSocket::pointer socket)
{
    while (socket->getReadyState() == WebSocket::OPEN && !isQuitting) {
        OutboundWebSocketMessage message;
        bool hasMessage = false;
        {
            std::lock_guard<std::mutex> lock(outboundWebSocketMessagesMutex);
            if (!outboundWebSocketMessages.empty()) {
                message = outboundWebSocketMessages.front();
                outboundWebSocketMessages.pop_front();
                hasMessage = true;
            }
        }
        if (!hasMessage) {
            return;
        }
        socket->send(message.payload);
        RememberDurableWebSocketMessage(message);
    }
}

void DiscardTransientOutboundWebSocketMessages()
{
    size_t discarded = 0;
    {
        std::lock_guard<std::mutex> lock(outboundWebSocketMessagesMutex);
        auto next = std::remove_if(
            outboundWebSocketMessages.begin(),
            outboundWebSocketMessages.end(),
            [&discarded](const OutboundWebSocketMessage& message) {
                if (message.durable) {
                    return false;
                }
                ++discarded;
                return true;
            });
        outboundWebSocketMessages.erase(next, outboundWebSocketMessages.end());
    }
    if (discarded > 0) {
        Log("Discarded %zu transient WebSocket messages after disconnect", discarded);
    }
}

void QueueExitAfterWebSocketAck()
{
    if (!exitAfterWebSocketAck.exchange(false)) {
        return;
    }
    Log("Session-end acknowledgement sent; queueing graceful CS2 quit");
    QueueEngineCommand("quit");
}

void SendStatusOk() {
    json msg;
    msg["name"] = "status";
    msg["payload"] = "ok";
    SendMsg(msg);
}

void RestoreGameinfoFile() {
    std::ifstream filebackupFile(gameInfoBackupPath);
    if (!filebackupFile.good()) {
        Log("gameinfo.gi backup file doesn't exist");
        filebackupFile.close();
        return;
    }

    std::ofstream destination(gameInfoPath);
    destination << filebackupFile.rdbuf();

    filebackupFile.close();
    destination.close();

    int result = remove(gameInfoBackupPath.c_str());
    if (result == 0) {
        Log("Backup file deleted successfully");
    }
    else
    {
        Log("Error deleting backup file");
    }
}

void LoadSequencesFile(string demoPath) {
    std::lock_guard<std::mutex> lock(sequencesMutex);
    sequences = {};

    // A debug session never loads a produce plan. A Demo may carry a stale
    // sidecar, and using it would reintroduce tick skipping, automatic
    // recording and disconnect for interactive playback. Both the `playdemo`
    // WebSocket branch and the `+playdemo` launch option funnel through here.
    if (!debugSessionID.empty()) {
        Log("Debug session: ignoring sequence file for %s", demoPath.c_str());
        return;
    }

    string demoJsonPath = demoPath + ".json";
    if (FileExists(demoJsonPath)) {
        Log("Loading JSON file %s", demoJsonPath.c_str());
        std::ifstream jsonFile(demoJsonPath);
        json jsonSequences = json::parse(jsonFile);

        std::istringstream stream(jsonSequences.dump(2));
        string line;
        while (std::getline(stream, line)) {
            Log("%s", line.c_str());
        }

        if (jsonSequences.size() == 0) {
            Log("No sequences found in JSON file");
            return;
        }

        Log("Loading %d sequences", jsonSequences.size());
        for (auto jsonSequence : jsonSequences) {
            Sequence sequence;
            for (auto jsonAction : jsonSequence["actions"]) {
                Action action;
                action.tick = jsonAction["tick"];
                action.cmd = jsonAction["cmd"];
                TryParseActionMetadata(jsonAction, action.metadata);
                sequence.actions.push_back(action);
            }
            sequences.push(sequence);
            Log("Sequence with %d actions loaded", sequence.actions.size());
        }

        Log("%d sequences loaded", sequences.size());
    }
    else {
        Log("JSON sequences file not found at %s", demoJsonPath.c_str());
    }
}

void NewFrameStageNotify(void* thisptr, ClientFrameStage_t stage)
{    
    if (stage != ClientFrameStage_t::FRAME_RENDER_PASS) {
        originalFrameStageNotify(thisptr, stage);
        return;
    }

    if (isQuitting) {
        originalFrameStageNotify(thisptr, stage);
        return;
    }

    auto engine = GetEngine();
    if (engine == NULL) {
        // The hook can be installed before the engine interface is available;
        // log once instead of every rendered frame.
        static bool loggedMissingEngine = false;
        if (!loggedMissingEngine) {
            loggedMissingEngine = true;
            Log("Engine interface not found");
        }
        originalFrameStageNotify(thisptr, stage);
        return;
    }

    engineCommandReady = true;

    {
        // Drain under the lock, then execute after releasing it. A plugin
        // special action (for example Radar POV setup) may enqueue further
        // engine commands; executing while holding pendingCommandsMutex would
        // deadlock the game thread.
        std::vector<PendingEngineCommand> queued;
        {
            std::lock_guard<std::mutex> lock(pendingCommandsMutex);
            while (!pendingCommands.empty()) {
                queued.push_back(std::move(pendingCommands.front()));
                pendingCommands.pop();
            }
        }
        for (auto& item : queued) {
            if (item.debugPlayDemo) {
                HandleDebugPlayDemoOnGameThread(engine, item);
                continue;
            }
            if (item.debugBatch) {
                std::string firstError;
                for (auto& rawCmd : item.debugCommands) {
                    const std::string cmd = TrimWhitespace(rawCmd);
                    if (cmd.empty()) {
                        if (firstError.empty()) {
                            firstError = "命令为空";
                        }
                        continue;
                    }
                    std::string specialError;
                    if (TryHandlePluginSpecialCommand(cmd, specialError)) {
                        Log("Handled debug special command: %s", cmd.c_str());
                        if (!specialError.empty() && firstError.empty()) {
                            firstError = specialError;
                        }
                        continue;
                    }
                    Log("Executing debug command: %s", cmd.c_str());
                    engine->ExecuteClientCmd(0, cmd.c_str(), true);
                    Log("Executed debug command: %s", cmd.c_str());
                }
                // The receipt means the game thread processed the request, not
                // that an ordinary console command had an observable effect.
                SendMsg(BuildDebugCommandResultMessage(
                    item.debugRequestID,
                    firstError.empty() ? "executed" : "failed",
                    firstError));
                continue;
            }
            const std::string cmd = item.cmd;
            Log("Executing queued command: %s", cmd.c_str());
            std::string specialError;
            if (TryHandlePluginSpecialCommand(cmd, specialError)) {
                Log("Handled queued special command: %s", cmd.c_str());
            } else {
                engine->ExecuteClientCmd(0, cmd.c_str(), true);
                Log("Executed queued command: %s", cmd.c_str());
            }
        }
    }

    // Workaround to start demo playback when Steam is in offline mode, the +playdemo launch option doesn't work in this case.
    if (demoPath != NULL) {
        auto now = std::chrono::steady_clock::now();
        auto secondsSinceStart = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        if (!engine->IsPlayingDemo() && secondsSinceStart >= 8) {
            string cmd = "playdemo \"" + string(demoPath) + "\"";
            demoPath = NULL;
            Log("Force playing demo: %s", cmd.c_str());
            engine->ExecuteClientCmd(0, cmd.c_str(), true);
            Log("Forced playing demo: %s", cmd.c_str());
        }
    }

    // Handle capture-player-view delayed endmovie
    if (captureInProgress) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - captureStartTime).count();
        if (elapsed >= 1000) {
            Log("Ending movie capture");
            engine->ExecuteClientCmd(0, "endmovie", true);
            captureInProgress = false;
            json responseMsg;
            responseMsg["name"] = "capture-player-view-result";
            SendMsg(responseMsg);
        }
    }

    auto demo = engine->GetDemoFile();
    if (!debugSessionID.empty()) {
        // Observe the actual engine path, including requests while another
        // Demo is still playing. Do not relabel its frames as the new Demo.
        const bool playing = engine->IsPlayingDemo();
        const int tick = demo ? demo->GetDemoTick() : -1;
        const char* enginePath = engine->GetDemoFilePath();
        const std::string observedPath = enginePath ? enginePath : "";
        const bool confirmed = debugPlaybackGate.Observe(observedPath, playing && demo != NULL, tick);
        const std::string previousPath = activeDemoPath;
        if (confirmed) {
            activeDemoPath = debugPlaybackGate.TargetPath();
            ApplyDebugPlaybackCommands(engine);
        } else if (playing && !observedPath.empty()) {
            activeDemoPath = observedPath;
        }
        if (confirmed || playing != isPlayingDemo ||
            NormalizeDebugDemoPath(activeDemoPath) != NormalizeDebugDemoPath(previousPath)) {
            SendMsg(BuildDebugDemoStateMessage(debugSessionID, activeDemoPath, playing, tick));
        }
        isPlayingDemo = playing;
        currentTick = tick;
        // Interactive playback never executes the production tick sequences.
        // Also observe stop when the Demo file interface has disappeared.
        originalFrameStageNotify(thisptr, stage);
        return;
    }
    if (demo == NULL) {
        // The hook may be installed before the client loads a map/demo, so log
        // this once instead of every rendered frame.
        static bool loggedMissingDemoFile = false;
        if (!loggedMissingDemoFile) {
            loggedMissingDemoFile = true;
            Log("Demo file interface not found");
        }
        originalFrameStageNotify(thisptr, stage);
        return;
    }

    int newTick = demo->GetDemoTick();
    bool newIsPlayingDemo = engine->IsPlayingDemo();
    if (newIsPlayingDemo && !isPlayingDemo) {
        {
            std::lock_guard<std::mutex> lock(sequencesMutex);
            Log("[%d] Demo playback started, sequences %d", newTick, sequences.size());
        }
    }
    else if (!newIsPlayingDemo && isPlayingDemo) {
        {
            std::lock_guard<std::mutex> lock(sequencesMutex);
            Log("[%d] Demo playback stopped, sequences %d", newTick, sequences.size());
        }
    }

    isPlayingDemo = newIsPlayingDemo;
    if (!isPlayingDemo) {
        originalFrameStageNotify(thisptr, stage);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(sequencesMutex);
        if (newTick != currentTick && !sequences.empty()) {
            // Log("Tick: %d -> %d", currentTick.load(), newTick);

            Sequence& currentSequence = sequences.front();
            for (auto& action : currentSequence.actions) {
                // Tick: 4 -> 5
                // Tick: 5 -> 6
                // Tick: 6 -> 8
                // Tick: 8 -> 9
                // Some ticks may be skipped, we execute actions for all ticks between the current tick and the new tick.
                if (action.tick > newTick || action.tick <= currentTick) {
                    continue;
                }

                if (action.cmd == "pause_playback") {
                    Log("[%d] Pausing demo playback", newTick);
                    engine->ExecuteClientCmd(0, "demo_pause", true);
                    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
                    Log("[%d] Resuming demo playback", newTick);
                    engine->ExecuteClientCmd(0, "demo_resume", true);
                }
                else if (action.cmd == "go_to_next_sequence") {
                    Log("[%d] Going to next sequence, remaining sequences: %d", newTick, sequences.size() - 1);
                    sequences.pop();
                    engine->ExecuteClientCmd(0, "demo_gototick 0", true);
                    currentTick = -1;
                    break;
                }
                else {
                    std::string specialError;
                    if (TryHandlePluginSpecialCommand(action.cmd, specialError)) {
                        Log("[%d] Handled sequence cmd: %s", newTick, action.cmd.c_str());
                        if (!specialError.empty()) {
                            Log("[%d] Sequence cmd failed: %s (%s)", newTick, action.cmd.c_str(), specialError.c_str());
                        }
                        continue;
                    }
                    Log("[%d] Executing: %s", newTick, action.cmd.c_str());
                    engine->ExecuteClientCmd(0, action.cmd.c_str(), true);
                    Log("[%d] Executed: %s", newTick, action.cmd.c_str());

                    if (IsMirvRecordBoundaryCommand(action.cmd)) {
                        SendMsg(BuildRecordStatusMessage(activeDemoPath, newTick, action.cmd, action.metadata));
                    }
                    if (action.cmd == "disconnect") {
                        SendMsg(BuildDemoDoneMessage(activeDemoPath, "disconnect"));
                        activeDemoPath.clear();
                    }

                }
            }
        }
    }

    currentTick = newTick;

    originalFrameStageNotify(thisptr, stage);
}

// Install the FrameStageNotify hook as soon as the client interface is
// available. Queued command consumption must not wait for the player to enter a
// game, otherwise the debug workbench can never send its first `playdemo`.
// Attempted during plugin Connect and retried by the debug bootstrap worker
// until available; ClientFullyConnect retains the production fallback. The
// worker only installs the hook: engine calls and readiness stay on the game
// thread, and the WebSocket thread only transports messages.
static bool TryInstallClientFrameHook()
{
    std::lock_guard<std::mutex> lock(clientHookMutex);
    if (client != NULL) {
        return true;
    }
    if (factory == NULL) {
        return false;
    }
    ISource2Client* candidate = (ISource2Client*)factory("Source2Client002", NULL);
    if (candidate == NULL) {
        return false;
    }
    Log("Hooking FrameStageNotify");
    auto vtable = *(void***)candidate;
    originalFrameStageNotify = (FrameStageNotifyFn)vtable[36];
    PatchVTableEntry(vtable, 36, (void*)&NewFrameStageNotify);
    client = candidate;
    Log("Hooked FrameStageNotify");
    return true;
}

static void BootstrapDebugCommandConsumer()
{
    // A late client interface must become usable without a map/demo connection.
    // Stop after installation; the frame hook retries engine lookup itself.
    while (!isQuitting && !TryInstallClientFrameHook()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void HandleWebSocketMessage(const std::string& message)
{
    Log("[%d] Message received: %s", currentTick.load(), message.c_str());
    try {
        json msg = json::parse(message.c_str());
        if (!msg.is_object() || !msg.contains("name") || !msg["name"].is_string()) {
            Log("Ignoring malformed WebSocket command envelope");
            return;
        }

        std::string name = msg["name"];
        if (name == "playdemo") {
            if (!msg.contains("payload") || !msg["payload"].is_string()) {
                Log("Ignoring playdemo command with invalid payload");
                return;
            }
            SendStatusOk();

            string requestedDemoPath = msg["payload"];
            activeDemoPath = requestedDemoPath;

            LoadSequencesFile(requestedDemoPath);

            string cmd = "playdemo \"" + requestedDemoPath + "\"";
            QueueEngineCommand(cmd);
            SendMsg(BuildDemoStartedMessage(activeDemoPath));
        }
        else if (name == "capture-player-view") {
            Log("Capturing player view");
            QueueEngineCommand("getposcopy");
            // The "screenshot" command works only on Windows when the -tools launch option is set.
            // As a workaround, we use the startmovie command to take a screenshot.
            QueueEngineCommand("hideconsole");
            QueueEngineCommand("startmovie csdmcamera jpg");
            captureStartTime = std::chrono::steady_clock::now();
            captureInProgress = true;
        }
        else if (name == "end_produce_session") {
            if (!msg.contains("payload") || !msg["payload"].is_object() ||
                !msg["payload"].contains("request_id") || !msg["payload"]["request_id"].is_string()) {
                Log("Ignoring end_produce_session command with invalid payload");
                return;
            }
            std::string requestID = msg["payload"]["request_id"];
            if (requestID.empty()) {
                Log("Ignoring end_produce_session command with empty request_id");
                return;
            }
            // The WebSocket owner sends the acknowledgement before it queues
            // quit on the engine thread. This lets the host classify the
            // subsequent socket close as an expected session completion.
            SendMsg(BuildSessionExitAckMessage(requestID));
            exitAfterWebSocketAck = true;
            Log("Accepted graceful session end request id=%s", requestID.c_str());
        }
        else if (name == "debug_play_demo") {
            // Only a host that launched this game with CSDM_DEBUG_SESSION may
            // use the interactive debug protocol.
            if (debugSessionID.empty()) {
                Log("Ignoring debug_play_demo without CSDM_DEBUG_SESSION");
                return;
            }
            if (!msg.contains("payload") || !msg["payload"].is_object()) {
                Log("Ignoring debug_play_demo command with invalid payload");
                return;
            }
            const auto& payload = msg["payload"];
            if (!payload.contains("request_id") || !payload["request_id"].is_string() ||
                !payload.contains("demo_path") || !payload["demo_path"].is_string()) {
                Log("Ignoring debug_play_demo command with invalid fields");
                return;
            }
            std::string requestID = payload["request_id"];
            std::string demoPath = payload["demo_path"];
            if (requestID.empty() || demoPath.empty()) {
                Log("Ignoring debug_play_demo command with empty request_id or demo_path");
                return;
            }
            std::vector<std::string> commands;
            if (payload.contains("commands") && payload["commands"].is_array()) {
                for (const auto& entry : payload["commands"]) {
                    if (entry.is_string()) {
                        commands.push_back(entry.get<std::string>());
                    }
                }
            }
            Log("Accepted debug_play_demo request id=%s demo=%s commands=%zu", requestID.c_str(), demoPath.c_str(), commands.size());
            QueueDebugPlayDemo(requestID, demoPath, std::move(commands));
        }
        else if (name == "debug_execute") {
            // Only a host that launched this game with CSDM_DEBUG_SESSION may
            // use the interactive debug protocol.
            if (debugSessionID.empty()) {
                Log("Ignoring debug_execute without CSDM_DEBUG_SESSION");
                return;
            }
            if (!msg.contains("payload") || !msg["payload"].is_object()) {
                Log("Ignoring debug_execute command with invalid payload");
                return;
            }
            const auto& payload = msg["payload"];
            if (!payload.contains("request_id") || !payload["request_id"].is_string() ||
                !payload.contains("commands") || !payload["commands"].is_array()) {
                Log("Ignoring debug_execute command with invalid fields");
                return;
            }
            std::string requestID = payload["request_id"];
            if (requestID.empty()) {
                Log("Ignoring debug_execute command with empty request_id");
                return;
            }
            std::vector<std::string> commands;
            for (const auto& entry : payload["commands"]) {
                if (entry.is_string()) {
                    commands.push_back(entry.get<std::string>());
                }
            }
            Log("Accepted debug_execute request id=%s commands=%zu", requestID.c_str(), commands.size());
            QueueDebugCommands(requestID, std::move(commands));
        }
        else {
            Log("Ignoring unknown WebSocket command: %s", name.c_str());
        }
    }
    catch (const std::exception& error) {
        Log("Ignoring malformed WebSocket command: %s", error.what());
    }
}

// Must be kept in sync with the WebSocket server default port in the host app.
const int DEFAULT_WEB_SOCKET_SERVER_PORT = 4574;

int GetWebSocketServerPort() {
    const char* portValue = getenv("CSDM_WS_PORT");
    if (portValue != NULL) {
        int port = atoi(portValue);
        if (port > 0) {
            return port;
        }
    }

    return DEFAULT_WEB_SOCKET_SERVER_PORT;
}

void ConnectToWebsocketServer() {
    int port = GetWebSocketServerPort();
    // easywsclient parses a path separately from the authority. Keep the
    // slash before the query string, otherwise it sends GET / and silently
    // drops process=game during the WebSocket handshake.
    string url = "ws://localhost:" + std::to_string(port) + "/?process=game";
    Log("Connecting to WebSocket server on port %d...", port);
    WebSocket::pointer socket = WebSocket::from_url(url);
    if (socket == NULL)
    {
        Log("Failed to connect to WebSocket server.");
        return;
    }

    Log("Connected to WebSocket server.");
    wsConnected = true;
    ReplayDurableWebSocketMessages(socket);
    bool debugReadySent = false;
    while (socket->getReadyState() != WebSocket::CLOSED && !isQuitting) {
        DrainOutboundWebSocketMessages(socket);
        QueueExitAfterWebSocketAck();
        // The game thread proves command consumption before we announce ready.
        // A reconnect re-enters this function, so the handshake is resent.
        if (!debugReadySent && !debugSessionID.empty() && engineCommandReady &&
            socket->getReadyState() == WebSocket::OPEN) {
            SendMsg(BuildDebugSessionReadyMessage(debugSessionID, DEBUG_PROTOCOL_VERSION));
            DrainOutboundWebSocketMessages(socket);
            debugReadySent = true;
            Log("Sent debug_session_ready for session %s", debugSessionID.c_str());
        }
        socket->poll(100);
        socket->dispatch([](const std::string& message) {
            HandleWebSocketMessage(message);
        });
        DrainOutboundWebSocketMessages(socket);
        QueueExitAfterWebSocketAck();
    }

    wsConnected = false;
    // session_exit_ack is intentionally not replayed: a reconnect must not
    // confirm a later session's command. The host falls back to PID shutdown
    // if this one-shot acknowledgement cannot complete the close handshake.
    exitAfterWebSocketAck = false;
    DiscardTransientOutboundWebSocketMessages();
    Log("Disconnected from WebSocket server.");
    delete socket;
}

void ConnectToWebsocketServerLoop() {
    while (true) {
        if (isQuitting) {
            break;
        }

        ConnectToWebsocketServer();

        if (!isQuitting) {
            Log("Retrying in 2s...");
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        }
    }
}

bool Connect(IAppSystem* appSystem, CreateInterfaceFn factoryFn)
{
    Log("Source2ServerConfig001::Connect entered");
    factory = factoryFn;
    if (serverConfigConnect == NULL) {
        Log("Source2ServerConfig001 original Connect is null; refusing to continue plugin initialization");
        return false;
    }
    bool result = serverConfigConnect(appSystem, factory);
    Log("Source2ServerConfig001::Connect returned %d", result);

    g_pCVar = (ICvar*)factory("VEngineCvar007", NULL);
    Log("VEngineCvar007 lookup returned %p", g_pCVar);
    // Try early installation; debug mode retries if the client appears later.
    // Engine lookup and the ready signal belong to the consuming game thread.
    TryInstallClientFrameHook();
    // Required to make the spec_lock_to_accountid command working since the 25/04/2024 update - it looks like the command has been hidden.
    // Also required to use the startmovie command.
    UnhideCommandsAndCvars();
#ifdef CON_COMMAND_ENABLED
    Log("Registering CSDM console commands");
    ConVar_Register();
    Log("Registered CSDM console commands");
#endif

    const char* debugSessionEnv = getenv("CSDM_DEBUG_SESSION");
    if (debugSessionEnv != NULL && debugSessionEnv[0] != '\0') {
        debugSessionID = debugSessionEnv;
        Log("Interactive debug protocol enabled for session %s", debugSessionID.c_str());
        debugBootstrapThread = new std::thread(BootstrapDebugCommandConsumer);
    }

    Log("Starting WebSocket connection thread");
    wsConnectionThread = new std::thread(ConnectToWebsocketServerLoop);

    RestoreGameinfoFile();

    return result;
}


void Shutdown()
{
    isQuitting = true;
    wsConnected = false;

    // Stop interface lookup/hook installation before tearing down the engine.
    if (debugBootstrapThread != NULL) {
        debugBootstrapThread->join();
        delete debugBootstrapThread;
        debugBootstrapThread = NULL;
    }

    // Best-effort: remove radar hooks before the rest of teardown.
    RadarPov_Uninstall();

    if (serverConfigShutdown != NULL) {
        serverConfigShutdown();
    }

#ifdef CON_COMMAND_ENABLED
    ConVar_Unregister();
#endif

    if (wsConnectionThread != NULL) {
        wsConnectionThread->join();
        delete wsConnectionThread;
        wsConnectionThread = NULL;
    }
}

void AssertInsecureParameterIsPresent()
{
    bool found = false;
    // Since the "Armory" update, calling CommandLine()->HasParm("-insecure") crashes the game when the parameter is not present.
    auto parameters = CommandLine()->GetParms();
    for (int i = 0; i < CommandLine()->ParmCount(); i++)
    {
        if (strcmp(parameters[i], "-insecure") == 0)
        {
            found = true;
            break;
        }
    }

    if (!found)
    {
        PluginError("CS:DM plugin loaded without the -insecure launch option.\n\nAborting.");
    }
}

void NewClientFullyConnect(void* thisptr, int playerSlot)
{
    Log("ClientFullyConnect: playerSlot=%d", playerSlot);

    // Hook FrameStageNotify to call engine commands from the engine thread since
    // it's not thread safe to call engine commands from another thread. Connect
    // already attempted this; retry here for clients that only appear later.
    TryInstallClientFrameHook();

    // One-time initialization for the first fully-connected client. It is
    // tracked separately from the hook so an early hook install during Connect
    // does not skip these commands.
    if (!clientFullyConnectInitialized.exchange(true)) {
        // Radar POV is opt-in via sequence JSON action "csdm_radar_pov" (idempotent).
        // Not installed here — avoids default-on and keeps config with other demo actions.
        RadarPov_SetLogger(&Log);
        RadarPov_SetEnabled(false);

        // Since the 23/05/2024 CS2 update, the demo playback UI is displayed by default.
        // We have to set the demo_ui_mode convar to 0 before starting the playback prevent the UI from being displayed.
        QueueEngineCommand("demo_ui_mode 0");
        QueueEngineCommand("sv_cheats 1"); // required to unlock commands such as getposcopy
    }

    originalClientFullyConnect(thisptr, playerSlot);
}

EXPORT void* CreateInterface(const char* pName, int* pReturnCode)
{
    if (shouldDeleteLogFile) {
        DeleteLogFile();
        shouldDeleteLogFile = false;
    }
    
    Log("CreateInterface called with %s", pName);
    if (serverCreateInterface == NULL)
    {
        AssertInsecureParameterIsPresent();

        const char* gameDirectory = Plat_GetGameDirectory();
        gameInfoPath = string(gameDirectory) + "/csgo/gameinfo.gi";
        gameInfoBackupPath = string(gameDirectory) + "/csgo/gameinfo.gi.backup";
        string libPath = string(gameDirectory) + SERVER_LIB_PATH;

        void* serverModule = LoadLib(libPath.c_str());
        if (serverModule == NULL)
        {
            PluginError("Could not load server lib %s : %s", libPath.c_str(), GetLastErrorString());
        }

        serverCreateInterface = (CreateInterfaceFn)GetLibAddress(serverModule, "CreateInterface");
        if (serverCreateInterface == NULL)
        {
            PluginError("Could not find CreateInterface : %s", GetLastErrorString());
        }
    }

    void* original = serverCreateInterface(pName, pReturnCode);
    auto vtable = *(void***)original;
    if (strcmp(pName, "Source2ServerConfig001") == 0)
    {
        serverConfigConnect = (AppSystemConnectFn)vtable[0];
        serverConfigShutdown = (AppSystemShutdownFn)vtable[4];
        PatchVTableEntry(vtable, 0, (void*)&Connect);
        PatchVTableEntry(vtable, 4, (void*)&Shutdown);
    } else if (strcmp(pName, "Source2GameClients001") == 0)
    {
        originalClientFullyConnect = (ClientFullyConnectFn)vtable[15];
        PatchVTableEntry(vtable, 15, (void*)&NewClientFullyConnect);
    }

    if (demoPath == NULL) {
        int paramCount = CommandLine()->ParmCount();
        for (int i = 0; i < paramCount; i++) {
            const char* param = CommandLine()->GetParm(i);
            if (strcmp(param, "+playdemo") == 0 && i + 1 < paramCount) {
                demoPath = CommandLine()->GetParm(i + 1);
                activeDemoPath = string(demoPath);
                LoadSequencesFile(string(demoPath));
                break;
            }
        }
    }

    return original;
}

#ifdef CON_COMMAND_ENABLED
CON_COMMAND(csdm_info, "Prints CS:DM plugin info")
{
    Log("Tick: %d", currentTick.load());
    Log("Is playing demo: %d", isPlayingDemo);
    Log("Radar POV: enabled=%d installed=%d (JSON cmd: csdm_radar_pov)",
        RadarPov_IsEnabled() ? 1 : 0,
        RadarPov_IsInstalled() ? 1 : 0);

    if (wsConnected) {
        Log("WebSocket connected");
    }
    else {
        Log("WebSocket not connected");
    }

    {
        std::lock_guard<std::mutex> lock(sequencesMutex);
        Log("Sequence count: %d", sequences.size());
    }

    auto engine = GetEngine();
    if (engine == NULL) {
        Log("Engine interface not found");
        return;
    }

    Log("Is connected %d", engine->IsConnected());
    Log("Is playing demo %d", engine->IsPlayingDemo());
    Log("Is recording demo %d", engine->IsRecordingDemo());
    Log("Map %s", engine->GetLevelNameShort());
    int width, height;
    engine->GetScreenSize(width, height);
    Log("Screen size: %dx%d", width, height);

    auto demo = engine->GetDemoFile();
    if (demo == NULL) {
        Log("Demo file interface not found");
        return;
    }

    Log("Demo tick: %d", demo->GetDemoTick());
}
#endif
