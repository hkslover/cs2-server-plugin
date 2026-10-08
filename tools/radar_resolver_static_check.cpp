// Offline radar-POV resolver validation harness.
//
// Maps a client.dll PE file image into memory (sections at their
// VirtualAddresses) and re-runs the production
// RadarPovResolver::ResolveRadarFunctions unchanged, so every resolution step
// can be revalidated after a CS2 update before a Windows build / in-game test.
//
// Build & run (see tools/run-radar-resolver-check.sh):
//   c++ -std=c++17 -O2 -DRADAR_POV_RESOLVER_STATIC_TEST \
//       tools/radar_resolver_static_check.cpp \
//       cs2-server-plugin/mem_utils.cpp \
//       cs2-server-plugin/radar_pov/radar_resolver.cpp \
//       -o /tmp/radar_resolver_check && /tmp/radar_resolver_check dll/client.dll

#define RADAR_POV_RESOLVER_STATIC_TEST 1

#include "../cs2-server-plugin/mem_utils.h"
#include "../cs2-server-plugin/radar_pov/radar_resolver.h"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

void TestLog(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
}

uint16_t Rd16(const std::vector<uint8_t>& b, size_t off)
{
    uint16_t v = 0;
    std::memcpy(&v, b.data() + off, sizeof(v));
    return v;
}

uint32_t Rd32(const std::vector<uint8_t>& b, size_t off)
{
    uint32_t v = 0;
    std::memcpy(&v, b.data() + off, sizeof(v));
    return v;
}

constexpr uint16_t kImageDosMagic = 0x5A4D;
constexpr uint32_t kImageNtSignature = 0x00004550;
constexpr uint16_t kImagePe32PlusMagic = 0x020B;
constexpr size_t kSectionHeaderSize = 40;
constexpr uint32_t kScnMemExecute = 0x20000000;

struct PeImage {
    std::vector<uint8_t> mapped;  // image laid out at VirtualAddresses
    uint32_t timestamp = 0;
    uint64_t imageBase = 0;
    MemUtils::ModuleInfo info = {};
};

bool LoadPeImage(const char* path, PeImage& out)
{
    FILE* f = fopen(path, "rb");
    if (f == nullptr) {
        fprintf(stderr, "cannot open %s\n", path);
        return false;
    }
    std::vector<uint8_t> file;
    char chunk[1 << 16];
    size_t n = 0;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        file.insert(file.end(), chunk, chunk + n);
    }
    fclose(f);
    if (file.size() < 0x40 || Rd16(file, 0) != kImageDosMagic) {
        fprintf(stderr, "not a PE file (DOS header)\n");
        return false;
    }
    const size_t peOff = Rd32(file, 0x3C);
    if (peOff + 24 + 224 > file.size() || Rd32(file, peOff) != kImageNtSignature) {
        fprintf(stderr, "bad NT signature\n");
        return false;
    }
    const size_t optOff = peOff + 24;
    if (Rd16(file, optOff) != kImagePe32PlusMagic) {
        fprintf(stderr, "not PE32+ (x64)\n");
        return false;
    }
    const uint16_t numSections = Rd16(file, peOff + 6);
    const uint16_t sizeOfOptional = Rd16(file, peOff + 20);
    out.timestamp = Rd32(file, peOff + 8);
    out.imageBase = 0;
    std::memcpy(&out.imageBase, file.data() + optOff + 24, sizeof(out.imageBase));
    const uint32_t sizeOfImage = Rd32(file, optOff + 56);
    const uint32_t sizeOfHeaders = Rd32(file, optOff + 60);
    if (sizeOfImage == 0 || sizeOfImage < sizeOfHeaders) {
        fprintf(stderr, "bad SizeOfImage\n");
        return false;
    }
    out.mapped.assign(sizeOfImage, 0);
    const size_t headerBytes = sizeOfHeaders < file.size() ? sizeOfHeaders : file.size();
    std::memcpy(out.mapped.data(), file.data(), headerBytes);

    const size_t sectionTable = optOff + sizeOfOptional;
    if (sectionTable + static_cast<size_t>(numSections) * kSectionHeaderSize > file.size()) {
        fprintf(stderr, "section table outside file\n");
        return false;
    }

    const uint8_t* execFallbackBase = nullptr;
    size_t execFallbackSize = 0;
    for (uint16_t i = 0; i < numSections; ++i) {
        const size_t sh = sectionTable + static_cast<size_t>(i) * kSectionHeaderSize;
        const uint32_t virtualSize = Rd32(file, sh + 8);
        const uint32_t virtualAddress = Rd32(file, sh + 12);
        const uint32_t sizeOfRawData = Rd32(file, sh + 16);
        const uint32_t pointerToRawData = Rd32(file, sh + 20);
        const uint32_t characteristics = Rd32(file, sh + 36);
        if (virtualAddress >= sizeOfImage || sizeOfRawData == 0) {
            continue;
        }
        size_t copyBytes = sizeOfRawData;
        if (pointerToRawData > file.size() ||
            copyBytes > file.size() - pointerToRawData) {
            copyBytes = pointerToRawData < file.size() ? file.size() - pointerToRawData : 0;
        }
        if (copyBytes > sizeOfImage - virtualAddress) {
            copyBytes = sizeOfImage - virtualAddress;
        }
        if (copyBytes != 0) {
            std::memcpy(out.mapped.data() + virtualAddress, file.data() + pointerToRawData,
                        copyBytes);
        }
        if ((characteristics & kScnMemExecute) == 0) {
            continue;
        }
        size_t textSize = virtualSize < sizeOfRawData ? sizeOfRawData : virtualSize;
        if (textSize > sizeOfImage - virtualAddress) {
            textSize = sizeOfImage - virtualAddress;
        }
        if (textSize == 0) {
            continue;
        }
        if (execFallbackBase == nullptr) {
            execFallbackBase = out.mapped.data() + virtualAddress;
            execFallbackSize = textSize;
        }
        if (std::memcmp(file.data() + sh, ".text", 5) == 0 && out.info.textBase == nullptr) {
            out.info.textBase = out.mapped.data() + virtualAddress;
            out.info.textSize = textSize;
        }
    }
    if (out.info.textBase == nullptr && execFallbackBase != nullptr) {
        out.info.textBase = const_cast<uint8_t*>(execFallbackBase);
        out.info.textSize = execFallbackSize;
    }
    out.info.base = out.mapped.data();
    out.info.size = out.mapped.size();
    return out.info.textBase != nullptr;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <client.dll>\n", argv[0]);
        return 2;
    }
    PeImage pe;
    if (!LoadPeImage(argv[1], pe)) {
        return 2;
    }
    printf("static-check: %s PE-timestamp=0x%08X image-base=0x%llX image-size=0x%zX\n", argv[1],
           pe.timestamp, static_cast<unsigned long long>(pe.imageBase), pe.info.size);
    printf("static-check: .text RVA=0x%zX size=0x%zX\n",
           static_cast<size_t>(pe.info.textBase - pe.info.base), pe.info.textSize);

    // Mapping self-check: the cvar name string the resolver bootstraps from
    // must be present in the mapped image before resolution starts.
    const char* cvarName =
        MemUtils::FindCString(pe.info, "cl_radar_show_all_players_when_spectating");
    if (cvarName == nullptr) {
        fprintf(stderr, "static-check: mapping self-check failed: cvar name string "
                        "missing from mapped image\n");
        return 2;
    }
    printf("static-check: cvar name string RVA=0x%zX\n",
           static_cast<size_t>(cvarName - reinterpret_cast<const char*>(pe.info.base)));

    RadarPovResolver::SetLogger(&TestLog);

    RadarPovResolver::ResolvedState resolved;
    const bool ok = RadarPovResolver::ResolveRadarFunctions(pe.info, resolved);
    printf("\nstatic-check: ResolveRadarFunctions -> %s\n", ok ? "PASS" : "FAIL");
    if (ok) {
        const auto base = reinterpret_cast<uintptr_t>(pe.info.base);
        const auto rva = [&](uintptr_t p) {
            return static_cast<unsigned long long>(p - base);
        };
        const auto& f = resolved.functions;
        printf("radar_update           RVA=0x%llX\n", rva(reinterpret_cast<uintptr_t>(f.radarUpdate)));
        printf("getLocal               RVA=0x%llX\n", rva(reinterpret_cast<uintptr_t>(f.getLocal)));
        printf("getObs                 RVA=0x%llX\n",
               rva(reinterpret_cast<uintptr_t>(f.getObserverTarget)));
        printf("getPlayerSlot           RVA=0x%llX",
               f.getPlayerSlot == nullptr
                   ? 0ULL
                   : rva(reinterpret_cast<uintptr_t>(f.getPlayerSlot)));
        printf("\nfindPlayerBySlot        RVA=0x%llX\n",
               f.findPlayerBySlot == nullptr
                   ? 0ULL
                   : rva(reinterpret_cast<uintptr_t>(f.findPlayerBySlot)));
        printf("getEntityBySlot        RVA=0x%llX\n",
               rva(reinterpret_cast<uintptr_t>(f.getEntityBySlot)));
        printf("isSlotEnemyOf          RVA=0x%llX\n",
               rva(reinterpret_cast<uintptr_t>(f.isSlotEnemyOf)));
        printf("setRadarIconType       RVA=0x%llX\n",
               rva(reinterpret_cast<uintptr_t>(f.setRadarIconType)));
        printf("radarIconColor         RVA=0x%llX\n",
               rva(reinterpret_cast<uintptr_t>(f.radarIconColor)));
        printf("getCompColorArgb       RVA=0x%llX\n",
               rva(reinterpret_cast<uintptr_t>(f.getCompColorArgb)));
        printf("resolvePlayerByIndex   RVA=0x%llX\n",
               rva(reinterpret_cast<uintptr_t>(f.resolvePlayerByIndex)));
        printf("demo/HLTV state global RVA=0x%llX\n",
               static_cast<unsigned long long>(resolved.radarDemoStateGlobalSlot - base));
        printf("show-all flag offset   0x%zX\n",
               static_cast<size_t>(resolved.radarShowAllFlagOffset));
    }
    return ok ? 0 : 1;
}
