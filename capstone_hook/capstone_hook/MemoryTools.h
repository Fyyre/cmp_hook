#pragma once
const int MOD_ADLER = 65521;
class MemoryTools
{
public:
	static void Protect(void *addr, size_t len, DWORD protect, DWORD *oldProtect);
	static void WriteInstruction(BYTE opcode, void * addr, void * new_addr, int nop, bool vp = true);
	static void WriteMemory(void * addr, unsigned char *data, int len, bool vp = true);
	static __forceinline void WriteJUMP(void * addr, void * new_addr, int nop, bool vp = true) { MemoryTools::WriteInstruction(0xE9, addr, new_addr, nop, vp); };
	static __forceinline void WriteCALL(void * addr, void * new_addr, int nop, bool vp = true) { MemoryTools::WriteInstruction(0xE8, addr, new_addr, nop, vp); };
	static __forceinline void WriteDWORD(void * addr, DWORD value, bool vp = true) { MemoryTools::WriteMemory(addr, (unsigned char *)&value, 4, vp); };
	static __forceinline void WriteBYTE(void * addr, unsigned char value, bool vp = true) { MemoryTools::WriteMemory(addr, &value, 1, vp); };
	static __forceinline void WriteNOP(void * addr, int count, bool vp = true) { for (int i = 0; i<count; i++)		MemoryTools::WriteBYTE((void *)((__int64)addr + i), 0x90, vp); };
	static __forceinline void bitsetn(int & i, unsigned bitposition) { i |= 1 << (bitposition); }
	static __forceinline void bitclearn(int & i, unsigned bitposition) { i &= ~(1 << bitposition); }
	static __forceinline INT32 readbitn(INT32 i, unsigned bitposition) { return (i >> (bitposition)) & 1; }
	static __forceinline unsigned int adler32(unsigned char *data, unsigned int len)
	{
		unsigned int a = 1, b = 0;
		size_t index;

		/* Process each byte of the data in order */
		for (index = 0; index < len; ++index)
		{
			a = (a + data[index]) % MOD_ADLER;
			b = (b + a) % MOD_ADLER;
		}

		return (b << 16) | a;
	};
	static __forceinline unsigned int jenkins(char *key, size_t len)
	{
		unsigned hash, i;
		for (hash = i = 0; i < len; ++i)
		{
			hash += key[i];
			hash += (hash << 10);
			hash ^= (hash >> 6);
		}
		hash += (hash << 3);
		hash ^= (hash >> 11);
		hash += (hash << 15);
		return hash;
	};
};