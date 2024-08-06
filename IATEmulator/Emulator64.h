#include <iostream>
#include <Windows.h>
#include "pluginmain.h"
#include "Emulator.h"


class Emulator64 : public Emulator
{
public:

	Emulator64();
	virtual ~Emulator64();

	bool Initialize(unsigned char* data, size_t size, uintptr_t address) override;
	void Deinitialize() override;

	bool InitRegs() override;

	uintptr_t GetCIP() override;
	bool SetCIP(uintptr_t ip) override;

	uc_err Run() override;
	bool Stop() override;
	
};