#include "Emulator.h"

Emulator::Emulator()
{

}

Emulator::~Emulator()
{
	
}

void Emulator::SetExcetionHandler(EXCEPTION_HANDLER exceptionHandler)
{
	m_err = uc_hook_add(m_uc, &m_exceptionHook,
		UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
		(void*)exceptionHandler, this, 1, 0);
}

void Emulator::SetCodeCallBack(CODE_CALLBACK cb)
{
	m_err = uc_hook_add(m_uc, &m_codeHook, UC_HOOK_CODE, cb, this, 1, 0);
}

void Emulator::ClearCodeCallBack()
{
	uc_hook_del(m_uc, m_codeHook);
	m_codeHook = 0;
}

uintptr_t Emulator::ReadReg(unsigned int reg)
{
	uintptr_t value = 0;
	m_err = uc_reg_read(m_uc, reg, &value);

	return value;
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
