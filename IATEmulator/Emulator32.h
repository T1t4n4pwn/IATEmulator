#pragma once
#include "Emulator.h"

class Emulator32 : public Emulator {
public:

	Emulator32();
	virtual ~Emulator32();

	bool Initialize(unsigned char* data, size_t size, uintptr_t address) override;
	void Deinitialize() override;
	bool InitRegs() override;
	uintptr_t GetCIP() override;
	bool SetCIP(uintptr_t ip) override;
	uc_err Run() override;
	bool Stop() override;

};