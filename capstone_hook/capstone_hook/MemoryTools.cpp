#include "stdafx.h"
#include "MemoryTools.h"

void MemoryTools::Protect(void *addr, size_t len, DWORD protect, DWORD *oldProtect)
{
	//VMProtectBeginMutation(__FUNCSIG__);
	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, false, GetCurrentProcessId());
	if (hProcess)
		VirtualProtectEx(hProcess, addr, len, protect, oldProtect);
	//VMProtectEnd();
}

void MemoryTools::WriteInstruction(BYTE opcode, void *addr, void *new_addr, int nop, bool vp)
{
	//VMProtectBeginMutation(__FUNCSIG__);
	MemoryTools::WriteBYTE(addr, opcode);
	MemoryTools::WriteDWORD((void *)((__int64)addr + 1), (DWORD)((__int64)new_addr - ((__int64)addr + 5))); // truncation naughty naughty (shut up ms)
	MemoryTools::WriteNOP((void *)((__int64)addr + 5), nop);
	//VMProtectEnd();
}

void MemoryTools::WriteMemory(void *addr, unsigned char *data, int len, bool vp)
{
	//VMProtectBeginMutation(__FUNCSIG__);
	DWORD oldProtect = 0;
	MemoryTools::Protect(addr, len, PAGE_WRITECOPY, &oldProtect);

	unsigned char *mem = (unsigned char *)addr;
	for (int i = 0; i<len; i++) {
		mem[i] = data[i];
	}

	MemoryTools::Protect(addr, len, oldProtect, &oldProtect);
	//VMProtectEnd();
}