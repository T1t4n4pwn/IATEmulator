#pragma once
#include <iostream>
#include <unicorn/unicorn.h>

#include "Utils.h"

typedef bool (*EXCEPTION_HANDLER)(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
typedef void (*CODE_CALLBACK)(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);

class Emulator {
public:

	Emulator();
	~Emulator();

	virtual bool Initialize(unsigned char* data, size_t size, uintptr_t address) = 0;
	virtual void Deinitialize() = 0;
	virtual bool InitRegs() = 0;

	virtual uintptr_t GetCIP() = 0;
	virtual bool SetCIP(uintptr_t ip) = 0;

	virtual uc_err Run() = 0;
	virtual bool Stop() = 0;

	void SetExcetionHandler(EXCEPTION_HANDLER exceptionHandler);
	void SetCodeCallBack(CODE_CALLBACK cb);
	void ClearCodeCallBack();

	uintptr_t ReadReg(unsigned int reg);
	bool WriteReg(unsigned int reg, uintptr_t value);

	bool ReadMemory(unsigned int address, unsigned int size, unsigned char* buffer);
	bool WriteMemory(unsigned int address, unsigned int size, unsigned char* buffer);

	uintptr_t GetEmulationResult() { return m_emulationAddress; }
	uint8_t GetEmulationType() { return m_invokeType; }
	uint8_t GetEmulationOffset() { return m_invokeOffset; }

protected:
	uc_engine* m_uc;
	uc_err m_err;

	uintptr_t m_memAddr;
	uintptr_t m_memSize;

	const int kStackSize = 0x10000;
	const uintptr_t kStackAddr = 0x100000;

	const uintptr_t kRegsBufferAddr = 0x150000;
	const uintptr_t kRegsBufferSize = 0x15000;

	uc_hook m_exceptionHook;
	uc_hook m_codeHook;

	uintptr_t m_emulationAddress;
	uint8_t m_invokeType; //0=jmp 1=call
	uint8_t m_invokeOffset;

};
