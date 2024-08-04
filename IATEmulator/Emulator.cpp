#include "Emulator.h"
#include "plugin.h"

Emulator::Emulator()
{


#ifdef _WIN64
	m_err = uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
#else
	m_err = uc_open(UC_ARCH_X86, UC_MODE_32, &m_uc);
#endif 
	if (m_err != UC_ERR_OK) {
		throw std::runtime_error("Failed to construct emulator");
	}
}

Emulator::~Emulator()
{
	Deinitialize();
	uc_hook_del(m_uc, m_exceptionHook);
	uc_close(m_uc);
}

bool Emulator::Initialize(unsigned char* data, size_t size, uintptr_t address)
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

#ifdef _WIN64
	bool isSuccess = WriteReg(UC_X86_REG_RSP, kStackAddr + 0x5000);
#else
	bool isSuccess = WriteReg(UC_X86_REG_ESP, kStackAddr + 0x5000);
#endif

	if (!isSuccess) {
		return false;
	}

	m_err = uc_mem_map(m_uc, kRegsBufferAddr, kRegsBufferSize, UC_PROT_ALL);
	if (m_err != UC_ERR_OK) {
		throw std::runtime_error("Failed to initialize emulator");
	}

	return true;
}

void Emulator::Deinitialize()
{
	uc_mem_unmap(m_uc, kStackAddr, kStackSize);
	uc_mem_unmap(m_uc, m_memAddr, m_memSize);
	uc_mem_unmap(m_uc, kRegsBufferAddr, kRegsBufferSize);
}

bool Emulator::InitRegs()
{
	static uint8_t* zeros = nullptr;
	if (zeros == nullptr) {
		zeros = new uint8_t[kRegsBufferSize]{ 0 };
	}

	bool isSuccesss = true;

	isSuccesss &= WriteMemory(kRegsBufferAddr, kRegsBufferSize, zeros);

	isSuccesss &= WriteMemory(kStackAddr, kStackSize, zeros);

#ifdef _WIN64
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
#else
	isSuccesss &= WriteReg(UC_X86_REG_EAX, (kRegsBufferAddr + 0));
	isSuccesss &= WriteReg(UC_X86_REG_EBX, (kRegsBufferAddr + 0x1000));
	isSuccesss &= WriteReg(UC_X86_REG_ECX, (kRegsBufferAddr + 0x2000));
	isSuccesss &= WriteReg(UC_X86_REG_EDX, (kRegsBufferAddr + 0x3000));
	isSuccesss &= WriteReg(UC_X86_REG_ESI, (kRegsBufferAddr + 0x5000));
	isSuccesss &= WriteReg(UC_X86_REG_EDI, (kRegsBufferAddr + 0x6000));
	isSuccesss &= WriteReg(UC_X86_REG_EBP, (kRegsBufferAddr + 0x7000));

#endif // _WIN64


	return m_err == UC_ERR_OK;
}

bool Emulator::GetCIP(uintptr_t& ip)
{
#ifdef _WIN64
	m_err = uc_reg_read(m_uc, UC_X86_REG_RIP, &ip);
#else
	m_err = uc_reg_read(m_uc, UC_X86_REG_EIP, &ip);
#endif
	return m_err == UC_ERR_OK;
}

bool Emulator::SetCIP(uintptr_t ip)
{
#ifdef _WIN64
	m_err = uc_reg_write(m_uc, UC_X86_REG_RIP, (const void*)&ip);
#else
	m_err = uc_reg_write(m_uc, UC_X86_REG_EIP, (const void*)&ip);
#endif
	return m_err == UC_ERR_OK;
}

bool Emulator::ReadReg(unsigned int reg, uintptr_t& value)
{
	m_err = uc_reg_read(m_uc, reg, &value);

	return m_err == UC_ERR_OK;
}
bool Emulator::WriteReg(unsigned int reg, uintptr_t value)
{
	m_err = uc_reg_write(m_uc, reg, &value);
	return m_err == UC_ERR_OK;
}

bool Emulator::ReadMemory(unsigned int address, unsigned int size, unsigned char* buffer)
{
	m_err = uc_mem_read(m_uc, address, buffer, size);
	return m_err == UC_ERR_OK;
}

bool Emulator::WriteMemory(unsigned int address, unsigned int size, unsigned char* buffer)
{
	m_err = uc_mem_write(m_uc, address, buffer, size);
	return m_err == UC_ERR_OK;
}

uc_err Emulator::Run()
{
	uintptr_t ip = 0;
	GetCIP(ip);
	uintptr_t EmuCSP = 0;
	if(!ReadReg(UC_X86_REG_ESP, EmuCSP))
	{
		throw std::runtime_error("Failed to Get Stack");
	}

	if (!InitRegs()) {
		throw std::runtime_error("Failed to run emulator");
	}
	//m_err = uc_emu_start(m_uc, ip, m_memAddr+m_memSize, 0, 0);
	m_err = uc_emu_start(m_uc, ip, 0xFFFFFFFFFFFFFFFF, 0, 0);
	//Reset();
	uintptr_t Finalip = 0;
	GetCIP(Finalip);
	//dprintf("err= %d\n", m_err);
	dprintf("StartEmulation Addr = %llx,Final Pause at :%llx\n", ip, Finalip);
	m_EmulationAddress = Finalip;

	uintptr_t FinalCSP = 0;
	if (!ReadReg(UC_X86_REG_ESP, FinalCSP))
	{
		throw std::runtime_error("Failed to Get Stack");
	}
	uintptr_t CspPtr = 0;
	this->ReadMemory(FinalCSP, sizeof(uintptr_t), (unsigned char*)&CspPtr);
	uintptr_t StackIndexDiff = CspPtr - ip;
	m_invoketype = IsInRange(StackIndexDiff - 5, 0, 2);
	if(m_invoketype)
		m_invokeoffset = FinalCSP == EmuCSP;
	else
		m_invokeoffset = FinalCSP == EmuCSP - sizeof(uintptr_t);
	return m_err;
}


void Emulator::SetExcetionHandler(EXCEPTION_HANDLER exceptionHandler)
{
	m_err = uc_hook_add(m_uc, &m_exceptionHook,
		UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
		(void*)exceptionHandler, this, 1, 0);
}

bool Emulator::Stop()
{
	m_err = uc_emu_stop(m_uc);
	return m_err == UC_ERR_OK;
}

void Emulator::Reset()
{
	for (auto i : m_addrMaps) {
		uc_mem_unmap(m_uc, i, PAGE_SIZE);
	}

}
