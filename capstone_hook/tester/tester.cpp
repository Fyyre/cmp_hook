// tester.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"

int _tmain(int argc, _TCHAR* argv[])
{
	LoadLibraryA("capstone_hook.dll");
	Sleep(15000);
	return 0;
}

