#pragma once

#include <cstddef>
#include <cstdint>

// Narrow, current-CS2 view of VEngineCvar007.
//
// Do not use the legacy HL2SDK ConCommandRef / ConVarRef wrappers here: their
// handle representation is private to CS2 and changed in the July 2026 game
// update. These declarations intentionally cover only the vtable entries and
// fields used by UnhideCommandsAndCvars, matching advancedfx-prop at commit
// 2e1366353c50d40150276c5d580b0eecb183881b.
struct CS2CvarEntry {
    const char* name;           // 0x00
    void* defaultValue;         // 0x08
    void* minValue;             // 0x10
    void* maxValue;             // 0x18
    const char* help;           // 0x20
    std::int16_t type;          // 0x28
    std::int16_t version;       // 0x2a
    std::uint32_t timesChanged; // 0x2c
    std::int64_t flags;         // 0x30
};

struct CS2CommandEntry {
    const char* name;      // 0x00
    const char* help;      // 0x08
    std::int64_t flags;    // 0x10
};

static_assert(offsetof(CS2CvarEntry, flags) == 0x30, "Unexpected CS2CvarEntry layout");
static_assert(offsetof(CS2CommandEntry, flags) == 0x10, "Unexpected CS2CommandEntry layout");

class CS2CvarAccess {
public:
    virtual void Unknown00() = 0;
    virtual void Unknown01() = 0;
    virtual void Unknown02() = 0;
    virtual void Unknown03() = 0;
    virtual void Unknown04() = 0;
    virtual void Unknown05() = 0;
    virtual void Unknown06() = 0;
    virtual void Unknown07() = 0;
    virtual void Unknown08() = 0;
    virtual void Unknown09() = 0;
    virtual void Unknown10() = 0;
    virtual void Unknown11() = 0;
    virtual void Unknown12() = 0;
    virtual void Unknown13() = 0;
    virtual void Unknown14() = 0;
    virtual void Unknown15() = 0;
    virtual void Unknown16() = 0;
    virtual void Unknown17() = 0;
    virtual void Unknown18() = 0;
    virtual void Unknown19() = 0;
    virtual void Unknown20() = 0;
    virtual void Unknown21() = 0;
    virtual void Unknown22() = 0;
    virtual void Unknown23() = 0;
    virtual void Unknown24() = 0;
    virtual void Unknown25() = 0;
    virtual void Unknown26() = 0;
    virtual void Unknown27() = 0;
    virtual void Unknown28() = 0;
    virtual void Unknown29() = 0;
    virtual void Unknown30() = 0;
    virtual void Unknown31() = 0;
    virtual void Unknown32() = 0;
    virtual void Unknown33() = 0;
    virtual void Unknown34() = 0;
    virtual void Unknown35() = 0;
    virtual void Unknown36() = 0;
    virtual void Unknown37() = 0;
    virtual void Unknown38() = 0;
    virtual void Unknown39() = 0;
    virtual void Unknown40() = 0;
    virtual CS2CvarEntry* GetCvar(std::size_t index) = 0; // vtable 41
    virtual void Unknown42() = 0;
    virtual void Unknown43() = 0;
    virtual CS2CommandEntry* GetCmd(std::size_t index) = 0; // vtable 44
};

constexpr std::size_t CS2_MAX_VALID_CVAR_COUNT = 8192;
