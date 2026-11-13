#include "../cs2-server-plugin/cdll_interfaces.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <type_traits>

static void Check(bool condition, const char *message)
{
    if (!condition)
    {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

using ExecuteSignature = void (ISource2EngineToClient::*)(int, const char *, bool, double, std::uint64_t);
static_assert(std::is_same<decltype(&ISource2EngineToClient::ExecuteClientCmd), ExecuteSignature>::value,
              "ExecuteClientCmd must carry all five native arguments");

// Emulate engine-owned objects with independently numbered vtable slots. This
// exercises dispatch and default argument forwarding without loading CS2 or
// constructing a mock subclass from the declarations under test. Run this on
// Windows x64 too: a native macOS run does not validate the MSVC calling ABI.
struct NativeObject
{
    void **vtable;
};

static NativeObject demoObject;
static NativeObject engineObject;
static int commandCalls = 0;

static int MaxClients(void *self)
{
    Check(self == &engineObject, "engine this pointer must survive dispatch");
    return 64;
}

static bool Yes(void *)
{
    return true;
}
static bool No(void *)
{
    return false;
}
static int StartTick(void *)
{
    return 96;
}
static int Tick(void *)
{
    return 75835;
}
static const char *Path(void *)
{
    return "C:/demos/match.dem";
}
static IDemoFile *Demo(void *)
{
    return reinterpret_cast<IDemoFile *>(&demoObject);
}

static void Execute(void *self, int slot, const char *commands, bool enabled, double inputTime, std::uint64_t timestamp)
{
    Check(self == &engineObject, "command this pointer must survive dispatch");
    Check(slot == 0 && enabled, "command flags must survive dispatch");
    if (commandCalls == 0)
    {
        Check(std::strcmp(commands, "playdemo \"C:/demos/match.dem\"") == 0, "playdemo command must survive dispatch");
        Check(std::isnan(inputTime), "default input time must be NaN");
        Check(timestamp == 0, "default SDL timestamp must be zero");
    }
    else
    {
        Check(inputTime == 1.25 && timestamp == 0x123456789abcdef0ULL, "explicit input metadata must survive dispatch");
    }
    ++commandCalls;
}

int main()
{
    void *engineSlots[70] = {};
    engineSlots[38] = reinterpret_cast<void *>(&MaxClients);
    engineSlots[39] = reinterpret_cast<void *>(&Yes);
    engineSlots[40] = reinterpret_cast<void *>(&No);
    engineSlots[42] = reinterpret_cast<void *>(&Yes);
    engineSlots[43] = reinterpret_cast<void *>(&Path);
    engineSlots[44] = reinterpret_cast<void *>(&No);
    engineSlots[51] = reinterpret_cast<void *>(&Execute);
    engineSlots[69] = reinterpret_cast<void *>(&Demo);
    engineObject.vtable = engineSlots;

    void *demoSlots[13] = {};
    demoSlots[2] = reinterpret_cast<void *>(&StartTick);
    demoSlots[3] = reinterpret_cast<void *>(&Tick);
    demoSlots[11] = reinterpret_cast<void *>(&Yes);
    demoSlots[12] = reinterpret_cast<void *>(&No);
    demoObject.vtable = demoSlots;

    auto engine = reinterpret_cast<ISource2EngineToClient *>(&engineObject);
    Check(engine->GetMaxClients() == 64, "GetMaxClients must use slot 38");
    Check(engine->IsInGame(), "IsInGame must use slot 39");
    Check(!engine->IsConnected(), "IsConnected must use slot 40");
    Check(engine->IsPlayingDemo(), "IsPlayingDemo must use slot 42");
    Check(std::strcmp(engine->GetDemoFilePath(), "C:/demos/match.dem") == 0, "GetDemoFilePath must use slot 43");
    Check(!engine->IsRecordingDemo(), "IsRecordingDemo must use slot 44");
    engine->ExecuteClientCmd(0, "playdemo \"C:/demos/match.dem\"", true);
    engine->ExecuteClientCmd(0, "sv_cheats 1", true, 1.25, 0x123456789abcdef0ULL);
    Check(commandCalls == 2, "both command calls must reach slot 51");

    auto demo = engine->GetDemoFile();
    Check(demo == reinterpret_cast<IDemoFile *>(&demoObject), "GetDemoFile must use slot 69");
    Check(demo->GetDemoStartTick() == 96, "GetDemoStartTick must use slot 2");
    Check(demo->GetDemoTick() == 75835, "GetDemoTick must use slot 3");
    Check(demo->IsPlayingDemo(), "Demo playback state must use slot 11");
    Check(!demo->IsDemoPaused(), "Demo pause state must use slot 12");
    std::cout << "Core interface regression checks passed\n";
}
