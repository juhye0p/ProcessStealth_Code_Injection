#pragma once
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <wchar.h>

#pragma warning(disable: 4996)
#pragma comment(lib, "ntdll.lib")

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define NewNtQuerySystemInformation_Size (ULONGLONG)AtherFunc - (ULONGLONG)NewNtQuerySystemInformation
#define lowerCase(c) c >= 65 && c <= 90 ? (wchar_t)c + 32 : c

void usage();
void elog(const char* log);
void slog(const char* name, const DWORD data);
void memFree(PVOID mem, SIZE_T size);
DWORD getPID(wchar_t* procName);
DWORD findOverwritePoint(PVOID address);