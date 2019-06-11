#include "stdafx.h"
#include <stdio.h>
#include <inttypes.h>
#include <vector>
#include "MemoryTools.h"
#include "capstone/capstone.h"
#pragma comment(lib, "capstone/capstone.lib")

// probably shouldnt assume that this will end up in 32bit memory space (it should though i think?)
unsigned char code_buffer[1024];
int code_buffer_offset = 0;

#define COMPARISON_VALUE 1000

void hookcmp(const uint8_t *ptr)
{
	csh handle;
	cs_insn *instructions;
	size_t instruction_count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		MessageBoxA(NULL, "cs_open error", "", MB_OK);
		return;
	}

	// disasm 32 bytes at the address
	instruction_count = cs_disasm(handle, ptr, 32, 0, 0, &instructions);
	if (instruction_count > 0) {
		// here goes nothing
		/*

		BYTE	MOD		REG			RM
		idx		7 6		5 4 3		2 1 0

		7C		0 1		1 1 1		1 0 0	// 8bit disp + sib!
		8B		1 0		1 1 1		0 0 0	// 32bit disp + no sib

		*/
		
		int modrm = (int)ptr[1];
		unsigned char sib;
		bool has_sib = false;
		int reg_offset = 0;

		if (MemoryTools::readbitn(modrm, 2) == 1 && MemoryTools::readbitn(modrm, 1) == 0 && MemoryTools::readbitn(modrm, 0) == 0) {
			// RM = 100 -> sib!
			has_sib = true;
			sib = ptr[2];
		}

		// if mod == 01, 8bit displacement
		if (MemoryTools::readbitn(modrm, 7) == 0 && MemoryTools::readbitn(modrm, 6) == 1) {
			reg_offset = (int)ptr[2 + (int)has_sib]; // bool to int calc wtf why do i do these things
		}
		// if mod == 10, 32bit displacement
		else if (MemoryTools::readbitn(modrm, 7) == 0 && MemoryTools::readbitn(modrm, 6) == 1) {
			reg_offset = *(int*)&ptr[2 + (int)has_sib]; // bool to int calc wtf why do i do these things
		}
		// mod 11 = cmp reg, x
		// mod 00 = cmp [reg], x
		// used? dunno
		else {
			MessageBoxA(NULL, "mod=00/11 ??", "", MB_OK);
		}

		// jump to code buffer
		int nop_size = 0;
		for (int i = 0; i < instruction_count; i++) {
			if (nop_size >= 5) {
				break;
			}
			nop_size += instructions[i].size;
		}
		MemoryTools::WriteJUMP((void *)ptr, (void *)(code_buffer + code_buffer_offset), nop_size - 5);

		// force mod to 10 to force 32bit displacement
		MemoryTools::bitsetn(modrm, 7); // 1
		MemoryTools::bitclearn(modrm, 6); // 0

		code_buffer[code_buffer_offset++] = 0x81; // compare opcode
		code_buffer[code_buffer_offset++] = (unsigned char)modrm;

		if (has_sib) {
			code_buffer[code_buffer_offset++] = sib;
		}

		// write register displacement
		code_buffer[code_buffer_offset] = reg_offset;
		code_buffer_offset += 4;

		// write our new comparison value
		*(int *)(code_buffer + code_buffer_offset) = COMPARISON_VALUE;
		code_buffer_offset += 4;

		int byte_count = instructions[0].size;
		if (byte_count < 5) {
			// <5 byte compares i hate you
			// making a few assumptions here about possible instruction sizes and also about short/far conditional jump parity
			// the only thing which should break this method is if there's a 3byte cmp + a 1 byte jump (pretty sure there are no 1-byte length jump operators including opcode but intel...)
			for (int i = 1; i < instruction_count; i++) {
				// 8bit conditional jump
				if (instructions[i].bytes[0] >= 0x70 && instructions[i].bytes[0] <= 0x7F) {
					code_buffer[code_buffer_offset++] = 0x0F;
					code_buffer[code_buffer_offset++] = instructions[i].bytes[0] + 0x10; // 0x0F prefix + opcode+0x10 = 32bit jump equivelant (i hope)

					__int64 new_address = (__int64)&ptr[byte_count + instructions[i].size] + instructions[i].bytes[1]; // after instruction + jump size
					new_address -= (__int64)&code_buffer[code_buffer_offset + 4];

					*(int *)(code_buffer + code_buffer_offset) = (int)new_address; // truncating again woo
					code_buffer_offset += 4;
				}
				// 32bit conditional jump
				else if (instructions[i].bytes[0] == 0x0F && (instructions[i].bytes[0] >= 0x70 && instructions[i].bytes[0] <= 0x7F)) {
					code_buffer[code_buffer_offset++] = 0x0F;
					code_buffer[code_buffer_offset++] = instructions[i].bytes[1];

					__int64 new_address = (__int64)&ptr[byte_count + instructions[i].size] + *(int *)&instructions[i].bytes[2]; // after instruction + jump size
					new_address -= (__int64)&code_buffer[code_buffer_offset + 4];

					*(int *)(code_buffer + code_buffer_offset) = (int)new_address; // truncating again woo
					code_buffer_offset += 4;
				}
				else {
					// assuming anything else is not a jump (bad bad bad what about jmp and jmp short or call (i'll add those if they become needed))
					memcpy(code_buffer + code_buffer_offset, ptr + byte_count, instructions[i].size);
					code_buffer_offset += instructions[i].size;
				}
				byte_count += instructions[i].size;
				if (byte_count >= 5)
					break;
			}
		}

		// jump back to server
		MemoryTools::WriteJUMP((void *)(code_buffer + code_buffer_offset), (void *)((__int64)ptr + byte_count), 0);
		code_buffer_offset += 5;
	}
}

void hook()
{
	hookcmp((const uint8_t *)0x406198);

	// better make our code buffer executable!
	DWORD oldProtect;
	VirtualProtect(code_buffer, sizeof(code_buffer), PAGE_EXECUTE_READ, &oldProtect);

	MessageBoxA(NULL, "Done, check it.", "", MB_OK);
}

BOOL __declspec(dllexport) APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}