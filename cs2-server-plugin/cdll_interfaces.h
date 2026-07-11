//===== Copyright 1996-2005, Valve Corporation, All rights reserved. ======//
//
// Purpose: Interfaces between the client.dll and engine
//
//===========================================================================//

// Credits @dtugend https://github.com/advancedfx/advancedfx-prop/blob/prop/cs2/sdk_src/public/cdll_int.h
// Updated for CS2 Update #1186 (2026-07-09) - vtable shifts due to new GetDemoFilePath and GetDemoStartTick
#include "interface.h"

abstract_class IDemoFile
{
public:
    virtual void _Unknown_000(void) = 0;
    virtual void _Unknown_001(void) = 0;
    virtual int GetDemoStartTick(void) = 0; //:002 (NEW in CS2 Update #1186)
    virtual int GetDemoTick(void) = 0; //:003 (same on both Windows and Linux now)
    virtual void _Unknown_004(void) = 0;
    virtual void _Unknown_005(void) = 0;
    virtual void _Unknown_006(void) = 0;
    virtual void _Unknown_007(void) = 0;
    virtual void _Unknown_008(void) = 0;
    virtual void _Unknown_009(void) = 0;
    virtual void _Unknown_010(void) = 0;
    virtual bool IsPlayingDemo(void) = 0; //:011
    virtual bool IsDemoPaused(void) = 0; //:012
};


abstract_class ISource2EngineToClient
{
public:
    virtual void _Unknown_000(void) = 0;
    virtual void _Unknown_001(void) = 0;
    virtual void _Unknown_002(void) = 0;
    virtual void _Unknown_003(void) = 0;
    virtual void _Unknown_004(void) = 0;
    virtual void _Unknown_005(void) = 0;
    virtual void _Unknown_006(void) = 0;
    virtual void _Unknown_007(void) = 0;
    virtual void _Unknown_008(void) = 0;
    virtual void _Unknown_009(void) = 0;
    virtual void _Unknown_010(void) = 0;
    virtual void _Unknown_011(void) = 0;
    virtual void _Unknown_012(void) = 0;
    virtual void _Unknown_013(void) = 0;
    virtual void _Unknown_014(void) = 0;
    virtual void _Unknown_015(void) = 0;
    virtual void _Unknown_016(void) = 0;
    virtual void _Unknown_017(void) = 0;
    virtual void _Unknown_018(void) = 0;
    virtual void _Unknown_019(void) = 0;
    virtual void _Unknown_020(void) = 0;
    virtual void _Unknown_021(void) = 0;
    virtual void _Unknown_022(void) = 0;
    virtual void _Unknown_023(void) = 0;
    virtual void _Unknown_024(void) = 0;
    virtual void _Unknown_025(void) = 0;
    virtual void _Unknown_026(void) = 0;
    virtual void _Unknown_027(void) = 0;
    virtual void _Unknown_028(void) = 0;
    virtual void _Unknown_029(void) = 0;
    virtual void _Unknown_030(void) = 0;
    virtual void _Unknown_031(void) = 0;
    virtual void _Unknown_032(void) = 0;
    virtual void _Unknown_033(void) = 0;
    virtual void _Unknown_034(void) = 0;
    virtual void _Unknown_035(void) = 0;
    virtual void _Unknown_036(void) = 0;
    virtual int GetMaxClients(void) = 0; //:037
    virtual bool IsInGame(void) = 0; //:038
    virtual bool IsConnected(void) = 0; //:039
    virtual void _Unknown_040(void) = 0;
    virtual void _Unknown_041(void) = 0;
    virtual bool IsPlayingDemo(void) = 0; //:042
    virtual const char* GetDemoFilePath(void) = 0; //:043 (NEW in CS2 Update #1186)
    virtual void _Unknown_044(void) = 0; // shifted from old :043
    virtual bool IsRecordingDemo(void) = 0; //:045 shifted from old :044
    virtual void _Unknown_046(void) = 0; // shifted from old :045 (Demo related)
    virtual void _Unknown_047(void) = 0;
    virtual void _Unknown_048(void) = 0;
    virtual void _Unknown_049(void) = 0;
    virtual void _Unknown_050(void) = 0;
    virtual void ExecuteClientCmd(int iUnk0MaybeSplitScreenSlotSetTo0, const char* pszCommands, bool bUnk2SetToTrue) = 0; //:051 shifted from old :050
    virtual void _Unknown_052(void) = 0;
    virtual void _Unknown_053(void) = 0;
    virtual void _Unknown_054(void) = 0;
    virtual void _Unknown_055(void) = 0;
    virtual void _Unknown_056(void) = 0;
    virtual void _Unknown_057(void) = 0;
    virtual void _Unknown_058(void) = 0;
    virtual void _Unknown_059(void) = 0;
    virtual void _Unknown_060(void) = 0;
    virtual void GetScreenSize(int& width, int& height) = 0; //:061 shifted from old :060
    virtual void _Unknown_062(void) = 0;
    virtual void _Unknown_063(void) = 0;
    virtual char const* GetLevelName(void) = 0; //:064 shifted from old :063
    virtual char const* GetLevelNameShort(void) = 0; //:065 shifted from old :064
    virtual void _Unknown_066(void) = 0;
    virtual void _Unknown_067(void) = 0;
    virtual void _Unknown_068(void) = 0;
    virtual IDemoFile* GetDemoFile(void) = 0; //:069 shifted from old :068, renamed from GetDemoPlayer
};

enum class ClientFrameStage_t : int
{
    // (haven't run any frames yet)
    FRAME_UNDEFINED = -1,
    FRAME_RENDER_PASS = 12   // Render a frame for display
    // There are more values in-between, but their meanings have changed and we did not confirm them yet.
};


abstract_class ISource2Client
{
public:
    virtual void _Unknown_000(void) = 0;
    virtual void _Unknown_001(void) = 0;
    virtual void _Unknown_002(void) = 0;
    virtual void _Unknown_003(void) = 0;
    virtual void _Unknown_004(void) = 0;
    virtual void _Unknown_005(void) = 0;
    virtual void _Unknown_006(void) = 0;
    virtual void _Unknown_007(void) = 0;
    virtual void _Unknown_008(void) = 0;
    virtual void _Unknown_009(void) = 0;
    virtual void _Unknown_010(void) = 0;
    virtual void _Unknown_011(void) = 0;
    virtual void _Unknown_012(void) = 0;
    virtual void _Unknown_013(void) = 0;
    virtual void _Unknown_014(void) = 0;
    virtual void _Unknown_015(void) = 0;
    virtual void _Unknown_016(void) = 0;
    virtual void _Unknown_017(void) = 0;
    virtual void _Unknown_018(void) = 0;
    virtual void _Unknown_019(void) = 0;
    virtual void _Unknown_020(void) = 0;
    virtual void _Unknown_021(void) = 0;
    virtual void _Unknown_022(void) = 0;
    virtual void _Unknown_023(void) = 0;
    virtual void _Unknown_024(void) = 0;
    virtual void _Unknown_025(void) = 0;
    virtual void _Unknown_026(void) = 0;
    virtual void _Unknown_027(void) = 0;
    virtual void _Unknown_028(void) = 0;
    virtual void _Unknown_029(void) = 0;
    virtual void _Unknown_030(void) = 0;
    virtual void _Unknown_031(void) = 0;
    virtual void _Unknown_032(void) = 0;
    virtual void _Unknown_033(void) = 0;
    virtual void _Unknown_034(void) = 0;
    virtual void _Unknown_035(void) = 0;
    virtual void FrameStageNotify(ClientFrameStage_t curStage);
};
