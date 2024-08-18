#pragma once
#include "pluginmain.h"

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();

void PluginMenuCallback(CBTYPE cbType, void* callbackInfo);
bool IsInRange(duint addr, duint start, duint end);
typedef enum {
	ACTION_CONFIG,
	ACTION_START,
	ACTION_SETSAVEPLACE,
}ACTION_TYPE;

extern bool g_isStart;

extern duint g_emulationStart;
extern duint g_emulationEnd;
