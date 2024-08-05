#include "plugin.h"
#include <iostream>
#include <algorithm>
#include "Emulator.h"

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
duint g_emulationStart = 0;
duint g_emulationEnd = 0; 
duint g_iatsaveplace = 0;
bool g_isStart = false;

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{


    return true;
}
void pluginStop()
{

    
}

void pluginSetup()
{

    _plugin_menuaddentry(hMenu, ACTION_CONFIG, "ConfigInit");
    _plugin_menuaddentry(hMenu, ACTION_START, "StartEmulation");
    _plugin_menuaddentry(hMenu, ACTION_SETSAVEPLACE, "IATSavePlace(Not FF15/25 Invoke)");
    _plugin_registercallback(pluginHandle, CB_MENUENTRY, PluginMenuCallback);

    dprintf("Test Plugin");
}

typedef enum : int {
    BRANCH_TYPE_DIRECT,
    BRANCH_TYPE_INDIRECT
}BRANCH_TYPE;

typedef struct {
    int Type;
    duint Addr;
}BRANCH_INFO;

std::atomic<duint> sleepAddrTmp = 0;
std::atomic_bool isLstrlen = false;

duint g_sleep_Addr = (duint)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
duint g_lstrlenA_Addr = (duint)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "lstrlenA");

bool IsInRange(duint addr, duint start, duint end)
{
    return (addr >= start && addr <= end);
}

bool SearchCall(Script::Module::ModuleSectionInfo info, std::vector<BRANCH_INFO>& result)
{
    result.clear();

    duint limit = info.addr + info.size;

    duint addr = info.addr;
    duint offset = 0;

    for (; offset < info.size; )
    {
        addr = Script::Pattern::FindMem(addr, info.size - offset, "E8");
        if (addr == 0) {
            break;
        }

        addr += 1;
        
        duint targetAddr = Script::Memory::ReadDword(addr) + 4 + addr;
        if (IsInRange(targetAddr, g_emulationStart, g_emulationEnd)) {
            BRANCH_INFO breach{ 0 };
            breach.Type = BRANCH_TYPE_DIRECT;
            //breach.Addr = targetAddr;
            breach.Addr = addr - 1;
            result.push_back(breach);
        }

        offset = addr - info.addr;
    }
    

    return result.size() > 0;
}

bool SearchFF15(Script::Module::ModuleSectionInfo info, std::vector<BRANCH_INFO>& result)
{

    result.clear();

    duint limit = info.addr + info.size;

    duint addr = info.addr;
    duint offset = 0;

    for (; offset < info.size; )
    {
        addr = Script::Pattern::FindMem(addr, info.size - offset, "FF 15");
        if (addr == 0) {
            break;
        }

        addr += 2;
        
#ifdef _WIN64
        duint targetAddr = Script::Memory::ReadDword(addr) + 4 + addr;
#else
        duint targetAddr = Script::Memory::ReadDword(addr);
#endif

        targetAddr = Script::Memory::ReadPtr(targetAddr);

        if (IsInRange(targetAddr, g_emulationStart, g_emulationEnd)) {
            BRANCH_INFO breach = { 0 };
            //breach.Addr = targetAddr;
            breach.Addr = addr - 2;
            breach.Type = BRANCH_TYPE_INDIRECT;
            result.push_back(breach);
        }

        offset = addr - info.addr;
    }

    return result.size() > 0;
}

bool SearchFF25(Script::Module::ModuleSectionInfo info, std::vector<BRANCH_INFO>& result)
{
    result.clear();

    duint limit = info.addr + info.size;

    duint addr = info.addr;
    duint offset = 0;

    for (; offset < info.size; )
    {
        addr = Script::Pattern::FindMem(addr, info.size - offset, "FF 25");
        if (addr == 0) {
             break;
        }

        addr += 2;

#ifdef _WIN64
        duint targetAddr = Script::Memory::ReadDword(addr) + 4 + addr;
#else
        duint targetAddr = Script::Memory::ReadDword(addr);
#endif

        targetAddr = Script::Memory::ReadPtr(targetAddr);

        if (IsInRange(targetAddr, g_emulationStart, g_emulationEnd)) {
            BRANCH_INFO breach = { 0 };

            breach.Type = BRANCH_TYPE_INDIRECT;
            //breach.Addr = targetAddr;
            breach.Addr = addr - 2;
            result.push_back(breach);
        }

        offset = addr - info.addr;
    }

    return result.size() > 0;
}


bool ExceptionHandler(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {

    Emulator* emu = (Emulator*)user_data;

    if (address == 0) {
        return false;
    }

    if (type == UC_MEM_READ_UNMAPPED || type == UC_MEM_WRITE_UNMAPPED)
    {
        uint8_t* data = new uint8_t[PAGE_SIZE]{ 0 };
        duint read = 0;
        Script::Memory::Read((duint)PAGE_ALIGN(address), data, PAGE_SIZE, &read);
        if (read != PAGE_SIZE) {
            return false;
        }
        
        uc_err err = uc_mem_map(uc, (duint)PAGE_ALIGN(address), PAGE_SIZE, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            return false;
        }

        err = uc_mem_write(uc, (duint)PAGE_ALIGN(address), data, PAGE_SIZE);
        if (err != UC_ERR_OK) {
            return false;
        }

      /*  emu->m_addrMaps.push_back((duint)PAGE_ALIGN(address));*/

        delete data;
    }
    else {
        //Oreans Specfic handler
        duint rspValue = 0;
        emu->ReadReg(UC_X86_REG_ESP, rspValue);
        duint retValue = 0;
        emu->ReadMemory(rspValue, sizeof(duint), (uint8_t*)&retValue);

        if (IsInRange(retValue, g_emulationStart, g_emulationEnd)) {
            duint cipValue = 0;
#ifdef _WIN64
            emu->ReadReg(UC_X86_REG_RIP, cipValue);
            
#else
            emu->ReadReg(UC_X86_REG_EIP, cipValue);
#endif
            if (cipValue == g_sleep_Addr) {


                //emu->SetCIP(retValue);
                //emu->WriteReg(UC_X86_REG_ESP, rspValue + sizeof(duint));

                sleepAddrTmp = retValue;
                uc_mem_map(uc, (duint)PAGE_ALIGN(cipValue), PAGE_SIZE, UC_PROT_ALL);

                return true;
            }
            if (cipValue == g_lstrlenA_Addr) {

                isLstrlen = true;
                uc_mem_map(uc, (duint)PAGE_ALIGN(cipValue), PAGE_SIZE, UC_PROT_ALL);

//#ifdef _WIN64
//                emu->WriteReg(UC_X86_REG_RAX, 0);
//#else
//                emu->WriteReg(UC_X86_REG_EAX, 0);
//#endif
//                emu->SetCIP(retValue);
//                emu->WriteReg(UC_X86_REG_ESP, rspValue + sizeof(duint));

                return true;
            }
            
            
        }

    }
    return true;
}

void CodeHook(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    
    //if (address > 0x200000000)
    //{
    //    std::cout <<"233"
    //}

    if (sleepAddrTmp.load()) {

        Emulator* emu = (Emulator*)user_data;

        duint rspValue = 0;
        emu->ReadReg(UC_X86_REG_ESP, rspValue);
        duint retValue = 0;
        emu->ReadMemory(rspValue, sizeof(duint), (uint8_t*)&retValue);

        emu->SetCIP(retValue);
        emu->WriteReg(UC_X86_REG_ESP, rspValue + sizeof(duint));

        uc_mem_unmap(uc, (duint)PAGE_ALIGN(g_sleep_Addr), PAGE_SIZE);

        sleepAddrTmp = 0;

        return;
    }
    
    if (isLstrlen) {
        Emulator* emu = (Emulator*)user_data;
  /*      duint cip = 0;
        emu->GetCIP(cip);

        if (cip < g_lstrlenA_Addr) {
            uc_mem_unmap(uc, (duint)PAGE_ALIGN(g_lstrlenA_Addr), PAGE_SIZE);
            isLstrlen = false;
        }*/
        duint rspValue = 0;
        emu->ReadReg(UC_X86_REG_ESP, rspValue);
        duint retValue = 0;
        emu->ReadMemory(rspValue, sizeof(duint), (uint8_t*)&retValue);

#ifdef _WIN64
        emu->WriteReg(UC_X86_REG_RAX, 0);
#else
        emu->WriteReg(UC_X86_REG_EAX, 0);
#endif
        emu->SetCIP(retValue);
        emu->WriteReg(UC_X86_REG_ESP, rspValue + sizeof(duint));
        isLstrlen = false;
        uc_mem_unmap(uc, (duint)PAGE_ALIGN(g_lstrlenA_Addr), PAGE_SIZE);
        return;
    }

    return;
}

void EmulationProcessing() {
    
    duint rip = Script::Register::GetCIP();
    Script::Module::ModuleSectionInfo info{0};

    for (size_t i = 0; i < 0x100; i++)
    {

        if (!Script::Module::SectionFromAddr(rip, i, &info)) {
            break;
        }
        
        duint start = info.addr;
        duint end = info.addr + info.size;
        
        if (IsInRange(rip, start, end)) {
            break;
        }

    }

    std::vector<BRANCH_INFO> callList;
    std::vector<BRANCH_INFO> ff15List;
    std::vector<BRANCH_INFO> ff25List;

    SearchCall(info, callList);
    SearchFF15(info, ff15List);
    SearchFF25(info, ff25List);

    Script::Module::ModuleInfo mainInfo{ 0 };

    if (!Script::Module::GetMainModuleInfo(&mainInfo)) {
        Script::Gui::Message(u8"获取主模块信息失败");
        return;
    }

    uint8_t* dump = new uint8_t[mainInfo.size]{0};
    size_t sizeRead = 0;

    Script::Memory::Read(mainInfo.base, dump, mainInfo.size, &sizeRead);
    if (sizeRead != mainInfo.size) {
        Script::Gui::Message(u8"读取内存失败");
        return;
    }

    dprintf("SearchCall: %d\n", callList.size());
    dprintf("SearchFF15: %d\n", ff15List.size());
    dprintf("SearchFF25: %d\n", ff25List.size());

    Emulator emu;
    emu.Initialize(dump, mainInfo.size, mainInfo.base);

    emu.SetExcetionHandler(ExceptionHandler);

    emu.SetCodeCallBack(CodeHook);

    for (size_t i = 0; i < ff15List.size(); i++)
    {
        emu.SetCIP(ff15List[i].Addr);
        uc_err err = emu.Run();
        duint EmulationResult = emu.GetEmulationResult();
        if (!(err == 11 || err == 0))
        {
            dprintf("There Might Be Something Wrong Errcode:%d,Emu Start Address at : %llx,Final Emulation Result:%llx\n", err,ff15List[i].Addr, EmulationResult);
            continue;
        }

        duint address = ff15List[i].Addr + 2;
#ifdef _WIN64
        duint targetAddr = Script::Memory::ReadDword(address) + 4 + address;
#else
        duint targetAddr = Script::Memory::ReadDword(addr);
#endif
        duint SizeWrite = 0;
        Script::Memory::Write(targetAddr,&EmulationResult,sizeof(duint),&SizeWrite);
        if (SizeWrite != sizeof(duint))
        {
            dprintf("Write Memory Failed,Address at : %llx\n", targetAddr);
            continue;
        }
    }

    for (size_t i = 0; i < ff25List.size(); i++)
    {
        emu.SetCIP(ff25List[i].Addr);
        uc_err err = emu.Run();
        duint EmulationResult = emu.GetEmulationResult();
        if (!(err == 11 || err == 0))
        {
            dprintf("There Might Be Something Wrong Errcode:%d,Emu Start Address at : %llx,Final Emulation Result:%llx\n", err, ff25List[i].Addr, EmulationResult);
            continue;
        }

        duint address = ff25List[i].Addr + 2;
#ifdef _WIN64
        duint targetAddr = Script::Memory::ReadDword(address) + 4 + address;
#else
        duint targetAddr = Script::Memory::ReadDword(addr);
#endif
        duint SizeWrite = 0;
        Script::Memory::Write(targetAddr, &EmulationResult, sizeof(duint), &SizeWrite);
        if (SizeWrite != sizeof(duint))
        {
            dprintf("Write Memory Failed,Address at : %llx\n", targetAddr);
            continue;
        }
    }
    for (size_t i = 0; i < callList.size(); i++)
    {
        emu.SetCIP(callList[i].Addr);
        uc_err err = emu.Run();
        duint EmulationResult = emu.GetEmulationResult();
        if (!(err == 11 || err == 0))
        {
            dprintf("There Might Be Something Wrong Errcode:%d,Emu Start Address at : %llx,Final Emulation Result:%llx\n", err, callList[i].Addr, EmulationResult);
            continue;
        }
        std::vector<uint8_t> FixedInstruction;
        bool IsHavePrefix = Script::Memory::ReadByte(callList[i].Addr - 1) == 0x48;
        if(IsHavePrefix)
            FixedInstruction.push_back(0x48);
        FixedInstruction.push_back(0xFF);
        FixedInstruction.push_back(emu.GetEmulationType()?0x15:0x25);
        duint TargetSavedPlace = g_iatsaveplace + i*sizeof(duint);
#ifdef _WIN64
        ULONG Offset = TargetSavedPlace - callList[i].Addr - 6 + emu.GetEmulationOffset();
#else
        ULONG Offset = TargetSavedPlace;
#endif
        for (int num = 0; num < 4; num++)
        {
            FixedInstruction.push_back(*(uint8_t*)((duint)&Offset + num));
        }
        duint SizeWrite = 0;
        Script::Memory::Write(callList[i].Addr - emu.GetEmulationOffset() - IsHavePrefix, FixedInstruction.data(), FixedInstruction.size(), &SizeWrite);
        Script::Memory::Write(TargetSavedPlace, (const void*)&EmulationResult,sizeof(duint), &SizeWrite);
    }
    delete dump;
}


void PluginMenuCallback(CBTYPE cbType, void* callbackInfo) 
{
    PLUG_CB_MENUENTRY* pMenu = (PLUG_CB_MENUENTRY*)callbackInfo;
    dprintf("%d\n", pMenu->hEntry);
    
    switch (pMenu->hEntry)
    {
    case ACTION_CONFIG:
    {
        Script::Gui::InputValue("VM Section Start: ", &g_emulationStart);
        Script::Gui::InputValue("VM Section End: ", &g_emulationEnd);
        break;
    }
    case ACTION_START:
    {

        if (g_isStart) {
            Script::Gui::Message(u8"模拟已开始");
            break;
        }

        if (Script::Module::GetMainModuleBase() == 0) {
            Script::Gui::Message(u8"未加载任何进程");
            break;
        }

        if (!Script::Memory::IsValidPtr(g_emulationStart) || !Script::Memory::IsValidPtr(g_emulationEnd)) {
            Script::Gui::Message(u8"开始或结束地址为无效内存地址");
            break;
        }

        int startProperty = Script::Memory::GetProtect(g_emulationStart);
        int endProperty = Script::Memory::GetProtect(g_emulationEnd);

        dprintf("%llx\n", startProperty);
        dprintf("%llx\n", endProperty);

        if ((startProperty & PAGE_EXECUTE) != 0 || (endProperty & PAGE_EXECUTE) != 0) {
            Script::Gui::Message(u8"地址无可执行权限");
            break;
        }

        g_isStart = !g_isStart;

        EmulationProcessing();

        g_isStart = !g_isStart;
        break;
    }
    case ACTION_SETSAVEPLACE:
    {
        Script::Gui::InputValue("Iat Save Place: ", &g_iatsaveplace);
    }
    default:
        break;
    }

    

}

