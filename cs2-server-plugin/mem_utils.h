#pragma once

// Shared PE / pattern helpers for CS2 client hooks (AfxHookSource2-style hex
// patterns with ?? wildcards). Safe to include from any Windows plugin TU.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace MemUtils {

struct ModuleInfo {
    uint8_t* base = nullptr;
    size_t size = 0;
    // Executable code range.  On Windows this is the PE .text section (or the
    // first executable section when a module has no literal .text section).
    // A zero range means callers should fall back to the complete module.
    uint8_t* textBase = nullptr;
    size_t textSize = 0;
};

// --- Module (Windows) ---

bool GetModuleInfo(const char* name, ModuleInfo& out);
uint32_t GetPeTimestamp(const ModuleInfo& mod);
bool IsInsideModule(const ModuleInfo& mod, uintptr_t addr);
bool IsInsideText(const ModuleInfo& mod, uintptr_t addr);
bool IsExecutableAddress(uintptr_t addr);

// Heuristic: pointer looks like a data/string object rather than code.
bool IsLikelyDataObject(const ModuleInfo& mod, uintptr_t addr);

// --- Exact bytes / C strings ---

const uint8_t* FindBytes(const uint8_t* begin, size_t size, const void* needle,
                         size_t needleSize);
const char* FindCString(const ModuleInfo& mod, const char* str);

// --- Hex pattern: "48 8B 0D ?? ?? ?? ?? FF 90 B0 02 00 00" ---
// ?? = any byte; spaces optional separators. Half-nibble ? supported.

bool MatchPattern(const uint8_t* p, size_t avail, const char* hex);
const uint8_t* FindPattern(const uint8_t* begin, size_t size, const char* hex);
std::vector<const uint8_t*> FindPatternAll(const uint8_t* begin, size_t size, const char* hex,
                                           size_t maxHits = 32);

// --- x64 instruction helpers ---

bool DecodeLeaRip(const uint8_t* insn, uintptr_t insnAddr, uintptr_t& targetOut,
                  size_t& sizeOut);
bool DecodeRel32Call(const uint8_t* insn, uintptr_t insnAddr, uintptr_t& targetOut);

std::vector<uintptr_t> FindLeaRipXrefs(const ModuleInfo& mod, uintptr_t target);
std::vector<uintptr_t> FindE8CallSites(const ModuleInfo& mod, uintptr_t fn);
std::vector<uintptr_t> CollectDirectCalls(const ModuleInfo& mod, uintptr_t fn,
                                          size_t maxScan = 0x800);

bool LooksLikePrologue(const uint8_t* p);
uintptr_t FindFunctionStart(const ModuleInfo& mod, uintptr_t anywhereInFn);
size_t ApproxFnSize(const ModuleInfo& mod, uintptr_t fn);

}  // namespace MemUtils
