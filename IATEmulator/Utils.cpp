#include "Utils.h"

bool IsInRange(uintptr_t addr, uintptr_t start, uintptr_t end)
{
    return (addr >= start && addr <= end);
}