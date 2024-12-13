#include "memory.h"

DWORD Memory::GetIdByName(const char* procName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return false;

	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };

	if (Process32First(hSnap, &pe))
	{
		do
		{
#ifdef UNICODE
			if(wcscmp(pe.szExeFile, procName) == 0)
#else
			if (strcmp(pe.szExeFile, procName) == 0)
#endif
			{
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnap, &pe));
	}
	CloseHandle(hSnap);
	return 0;
}

uintptr_t Memory::GetBaseAddress(const char* moduleName)
{
	DWORD dwModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, id);
	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnapshot, &ModuleEntry32)) 
	{
		do {
#ifdef UNICODE
			if(wcscmp(szModule, moduleName) == 0;)
#else
			if (strcmp(ModuleEntry32.szModule, moduleName) == 0) 
#endif
			{
				dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnapshot, &ModuleEntry32)); 


	}
	CloseHandle(hSnapshot);
	return dwModuleBaseAddress;
}

bool Memory::Attach(const char* procName)
{
	if (strlen(procName) == 0) return true;
	
	id = GetIdByName(procName);

	if (id == 0)
	{
		return false;
	}

	handle = OpenProcess(PROCESS_ALL_ACCESS, 0, id);
	return handle != nullptr;
}

void Memory::Detach()
{
	if (handle)
	{
		CloseHandle(handle);
	}

	if (!allocatedMemory.empty())
	{
		for (auto& allocatedMem : allocatedMemory)
		{
			FreeMemory((uintptr_t)allocatedMem);
		}
	}
	if (!heldMutex.empty())
	{
		for (auto& mutex : heldMutex)
		{
			ReleaseMutex(mutex);
			CloseHandle(mutex);
		}
	}
}

bool Memory::ChangeMemoryPage(const uintptr_t& address, const DWORD& newProtect, SIZE_T& size, DWORD* oldProtect)
{
	if (!InitializeNtdll()) return false;
	if (!handle) return false;

	PVOID baseAddress = reinterpret_cast<PVOID>(address);
	SIZE_T regionSize = size;

	NTSTATUS status = NtProtectVirtualMemory(handle, &baseAddress, &regionSize, newProtect, oldProtect);
	return status == 0;
}


bool Memory::IsMemoryOk(const uintptr_t& address)
{
	MEMORY_BASIC_INFORMATION mem_info;
	if (VirtualQueryEx(handle, reinterpret_cast<const void*>(address), &mem_info, sizeof(mem_info)) == sizeof(mem_info))
	{
		return mem_info.State == MEM_COMMIT && (mem_info.Type == MEM_PRIVATE || mem_info.Type == MEM_MAPPED);
	}
}

LPVOID Memory::AllocateMemory(size_t size)
{
	LPVOID allocated = VirtualAllocEx(handle, 0, size, MEM_COMMIT | MEM_RELEASE, PAGE_READWRITE);
	if (allocated != nullptr)
	{
		allocatedMemory.push_back(allocated);
	}

	return allocated;
}

bool Memory::FreeMemory(const uintptr_t& address)
{
	if (VirtualFreeEx(handle, (LPVOID)address, 0, MEM_RELEASE))
	{
		auto it = std::find(allocatedMemory.begin(), allocatedMemory.end(), (LPVOID)address);
		if (it != allocatedMemory.end())
		{
			allocatedMemory.erase(it);
		}

		return true;
	}
	else
	{
		return false;
	}
}

bool Memory::m_CreateMutex(const std::string& mutexName, const LPSECURITY_ATTRIBUTES& attributes, const bool& initialOwner)
{
	HANDLE mutex = CreateMutexA(attributes, initialOwner, mutexName.c_str());
	if (mutex != nullptr)
	{
		heldMutex.push_back(mutex);
		return true;
	}
	return false;
}

bool Memory::KillProcess(const char* processName)
{
	if (processName == "this")
	{
		ExitProcess(0);
	}

	std::unique_ptr<Memory> mem = std::make_unique<Memory>(processName);
	return TerminateProcess(mem->handle, 0);
}

Memory::Memory(const char* procName)
{
	if (strlen(procName) != 0) Attach(procName);
}

Memory::~Memory()
{
	Detach();
}