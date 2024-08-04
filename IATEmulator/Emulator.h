#include <iostream>
#include <Windows.h>
#include "pluginmain.h"

#include <unicorn/unicorn.h>

typedef bool (*EXCEPTION_HANDLER)(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

class Emulator
{
private:
	uc_engine* m_uc;
	uc_err m_err;

	uintptr_t m_memAddr;
	uintptr_t m_memSize;

	const int kStackSize = 0x10000;
	const uintptr_t kStackAddr = 0x100000;

	const uintptr_t kRegsBufferAddr = 0x150000;
	const uintptr_t kRegsBufferSize = 0x15000;

	uc_hook m_exceptionHook;

	uintptr_t m_EmulationAddress;
	uint8_t m_invoketype; //0=jmp 1=call
	uint8_t m_invokeoffset; 
public:
	Emulator();
	~Emulator();

	bool Initialize(unsigned char* data, size_t size, uintptr_t address);
	void Deinitialize();

	bool InitRegs();

	bool GetCIP(uintptr_t& ip);
	bool SetCIP(uintptr_t ip);

	bool ReadReg(unsigned int reg, uintptr_t& value);
	bool WriteReg(unsigned int reg, uintptr_t value);

	bool ReadMemory(unsigned int address, unsigned int size, unsigned char* buffer);
	bool WriteMemory(unsigned int address, unsigned int size, unsigned char* buffer);

	uc_err Run();
	bool Stop();

	void Reset();

	void SetExcetionHandler(EXCEPTION_HANDLER exceptionHandler);

	uintptr_t GetEmulationResult() {return m_EmulationAddress;}
	uint8_t GetEmulationType() {return m_invoketype;}
	uint8_t GetEmulationOffset() {return m_invokeoffset;}
	std::vector<duint> m_addrMaps;

};