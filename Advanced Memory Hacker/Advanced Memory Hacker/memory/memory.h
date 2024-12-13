#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <thread>
#include <fstream>
#include <string>
#include <memory>

#include "ntdll\ntdll.h"
#include "utils\functions\functions.h"

class Memory
{
public:
	HANDLE handle;
	DWORD id;
	uintptr_t base;

	std::string ProcName;

public:
	std::vector<LPVOID> allocatedMemory;
	std::vector<HANDLE> heldMutex;

public:
	static DWORD GetIdByName(const char* procName);
	uintptr_t GetBaseAddress(const char* moduleName);

	bool Attach(const char* procName);
	void Detach();

	bool ChangeMemoryPage(const uintptr_t& address, const DWORD& newProtect, SIZE_T& size, DWORD* oldProtect);
	bool IsMemoryOk(const uintptr_t& address);

	LPVOID AllocateMemory(size_t size);
	bool FreeMemory(const uintptr_t& address);

	bool m_CreateMutex(const std::string& mutexName, const LPSECURITY_ATTRIBUTES& attributes = 0, const bool& initialOwner = 1);

	template <typename Ty>
	Ty ReadMemory(const uintptr_t& address, bool checkOk = false)
	{
		Ty buffer = {};
		if (!InitializeNtdll()) return buffer;
		if (!this->handle) return buffer;

		if (!IsMemoryOk(address) && checkOk) return buffer;

		LPVOID addy = reinterpret_cast<LPVOID>(address);

		NtReadVirtualMemory(handle, addy, &buffer, sizeof(buffer), nullptr);
		return buffer;
	}

	template <typename Ty>
	bool WriteMemory(const uintptr_t& address, const Ty& buffer)
	{
		if (!InitializeNtdll()) {
			std::cout << "init?" << "\n";
			return false;
		}
		if (!this->handle) {
			std::cout << "handle?" << "\n";
			return false;
		}

		if (!IsMemoryOk(address)) {
			std::cout << "is ok?" << "\n";
			return false;
		}

		return NtWriteVirtualMemory(handle, reinterpret_cast<LPVOID>(address), (PVOID)&buffer, sizeof(buffer), nullptr) == 0;
	}
	template <typename Ty>
	bool WriteMemory(const uintptr_t& address, const Ty& buffer, size_t size)
	{
		std::cout << "hi\n";

		if (!InitializeNtdll()) {
			std::cerr << "Failed to initialize Ntdll!" << std::endl;
			return false;
		}

		/*if (!this->handle) {
			std::cerr << "Invalid process handle!" << std::endl;
			return false;
		}*/

		if (address == 0) {
			std::cerr << "Invalid address: 0x" << std::hex << address << std::dec << std::endl;
			return false;
		}

		if (!IsMemoryOk(address)) {
			std::cerr << "Memory at address 0x" << std::hex << address << std::dec << " is not ok!" << std::endl;
			return false;
		}

		// Debugging: Print buffer content
		std::cout << "Writing " << size << " bytes to memory at address 0x" << std::hex << address << std::dec << std::endl;

		return NtWriteVirtualMemory(handle, reinterpret_cast<LPVOID>(address), (PVOID)&buffer, size, nullptr) == 0;
	}

	static bool KillProcess(const char* processName = "this");

	bool StandardInject(const std::string& path);

public:
	Memory(const char* procName = "");
	~Memory();
	bool TheCheck();
};
inline std::unique_ptr<Memory> memory;