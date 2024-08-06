#include "Emulator64.h"
#include "plugin.h"

Emulator64::Emulator64()
{
	m_err = uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);

	if (m_err != UC_ERR_OK) {
		throw std::runtime_error("Failed to construct emulator");
	}
}

Emulator64::~Emulator64()
{
	Deinitialize();
	if (m_exceptionHook != NULL) {
		uc_hook_del(m_uc, m_exceptionHook);
	}
	if (m_codeHook != NULL) {
		uc_hook_del(m_uc, m_codeHook);
	}
	uc_close(m_uc);
}

bool Emulator64::Initialize(unsigned char* data, size_t size, uintptr_t address)
{
	m_memAddr = address;
	m_memSize = size;

	m_err = uc_mem_map(m_uc, m_memAddr, m_memSize, UC_PROT_ALL);
	if (m_err != UC_ERR_OK) {
		throw std::runtime_error("Failed to initialize emulator");
	}

	m_err = uc_mem_write(m_uc, m_memAddr, data, size);
	if (m_err != UC_ERR_OK) {
		throw std::runtime_error("Failed to initialize emulator");
	}


	m_err = uc_mem_map(m_uc, kStackAddr, kStackSize, UC_PROT_ALL);
	if (m_err != UC_ERR_OK) {
		throw std::runtime_error("Failed to initialize emulator");
	}

	bool isSuccess = WriteReg(UC_X86_REG_RSP, kStackAddr + 0x5000);

	if (!isSuccess) {
		return false;
	}

	m_err = uc_mem_map(m_uc, kRegsBufferAddr, kRegsBufferSize, UC_PROT_ALL);
	if (m_err != UC_ERR_OK) {
		throw std::runtime_error("Failed to initialize emulator");
	}

	return true;
}

void Emulator64::Deinitialize()
{
	uc_mem_unmap(m_uc, kStackAddr, kStackSize);
	uc_mem_unmap(m_uc, m_memAddr, m_memSize);
	uc_mem_unmap(m_uc, kRegsBufferAddr, kRegsBufferSize);
}

bool Emulator64::InitRegs()
{
	static uint8_t* zeros = nullptr;
	if (zeros == nullptr) {
		zeros = new uint8_t[kRegsBufferSize]{ 0 };
	}

	bool isSuccesss = true;

	isSuccesss &= WriteMemory(kRegsBufferAddr, kRegsBufferSize, zeros);

	isSuccesss &= WriteMemory(kStackAddr, kStackSize, zeros);

	isSuccesss &= WriteReg(UC_X86_REG_RAX, (kRegsBufferAddr + 0));
	isSuccesss &= WriteReg(UC_X86_REG_RBX, (kRegsBufferAddr + 0x1000));
	isSuccesss &= WriteReg(UC_X86_REG_RCX, (kRegsBufferAddr + 0x2000));
	isSuccesss &= WriteReg(UC_X86_REG_RDX, (kRegsBufferAddr + 0x3000));
	isSuccesss &= WriteReg(UC_X86_REG_RBP, (kRegsBufferAddr + 0x4000));
	isSuccesss &= WriteReg(UC_X86_REG_RSI, (kRegsBufferAddr + 0x5000));
	isSuccesss &= WriteReg(UC_X86_REG_RDI, (kRegsBufferAddr + 0x6000));
	isSuccesss &= WriteReg(UC_X86_REG_R8, (kRegsBufferAddr + 0x7000));
	isSuccesss &= WriteReg(UC_X86_REG_R9, (kRegsBufferAddr + 0x8000));
	isSuccesss &= WriteReg(UC_X86_REG_R10, (kRegsBufferAddr + 0x9000));
	isSuccesss &= WriteReg(UC_X86_REG_R11, (kRegsBufferAddr + 0xA000));
	isSuccesss &= WriteReg(UC_X86_REG_R12, (kRegsBufferAddr + 0xB000));
	isSuccesss &= WriteReg(UC_X86_REG_R13, (kRegsBufferAddr + 0xC000));
	isSuccesss &= WriteReg(UC_X86_REG_R14, (kRegsBufferAddr + 0xD000));
	isSuccesss &= WriteReg(UC_X86_REG_R15, (kRegsBufferAddr + 0xE000));


	return m_err == UC_ERR_OK;
}

uintptr_t Emulator64::GetCIP()
{
	uintptr_t ip = 0;

	m_err = uc_reg_read(m_uc, UC_X86_REG_RIP, &ip);
	return ip;
}

bool Emulator64::SetCIP(uintptr_t ip)
{
	m_err = uc_reg_write(m_uc, UC_X86_REG_RIP, (const void*)&ip);
	return m_err == UC_ERR_OK;
}

uc_err Emulator64::Run()
{
	uintptr_t ip = GetCIP();;
	uintptr_t emuCSP = ReadReg(UC_X86_REG_ESP);
	if(emuCSP == 0)
	{
		throw std::runtime_error("Failed to Get Stack");
	}

	if (!InitRegs()) {
		throw std::runtime_error("Failed to run emulator");
	}

	m_err = uc_emu_start(m_uc, ip, 0xFFFFFFFFFFFFFFFF, 0, 0);

	uintptr_t finalIp = GetCIP();

	dprintf("StartEmulation Addr = %llx,Final Pause at :%llx\n", ip, finalIp);
	m_emulationAddress = finalIp;

	uintptr_t finalCSP = ReadReg(UC_X86_REG_ESP);
	if (finalCSP == 0)
	{
		throw std::runtime_error("Failed to Get Stack");
	}
	uintptr_t cspPtr = 0;
	this->ReadMemory(finalCSP, sizeof(uintptr_t), (unsigned char*)&cspPtr);
	uintptr_t stackIndexDiff = cspPtr - ip;
	m_invokeType = IsInRange(stackIndexDiff - 5, 0, 2);
	if(m_invokeType)
		m_invokeOffset = finalCSP == emuCSP; //call
	else
		m_invokeOffset = finalCSP == emuCSP + sizeof(uintptr_t);
	return m_err;
}

bool Emulator64::Stop()
{
	m_err = uc_emu_stop(m_uc);
	return m_err == UC_ERR_OK;
}

