#include "MyLoadLibary.h"
#include <stdexcept>  
#include <memory>
#include <memory.h>
#include <vector>
#pragma once

# define minbufsize 62
# define startIndex 0x3C

using namespace std;

MyLoadLibary::MyLoadLibary(string filename){
	this->filename = filename;
}

HMODULE MyLoadLibary::Load() {
	HMODULE h;
	return h;
}

bool MyLoadLibary::ReadAndValidateHeaders() {
	HANDLE hFile;
	DWORD dwBytesRead = 0;
	LPCSTR file_lpcstr = static_cast<LPCSTR>(this->filename.c_str());
	hFile = CreateFileA(
		file_lpcstr,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		throw invalid_argument("Terminal failure: unable to open file for read.\n");
	}

	LARGE_INTEGER numofBytes;
	if (0 == GetFileSizeEx(hFile, &numofBytes)) {
		CloseHandle(hFile);
		throw invalid_argument("Terminal failure: " + to_string(GetLastError()) + '\n');
	}
	if (numofBytes.QuadPart > MAXDWORD) {
		throw invalid_argument("file is to big.");
	}
	this->filesizeinBytes = (DWORD)numofBytes.QuadPart;
	this->fb = FileBuffer(this->filesizeinBytes);

	if (!ReadFile(hFile, this->fb.filebuffer, this->filesizeinBytes, NULL, NULL)) {
		CloseHandle(hFile);
		throw invalid_argument("Terminal failure: " + to_string(GetLastError()) + '\n');
	}

	if (this->filesizeinBytes < minbufsize || this->fb.filebuffer[0] != 0x4D || this->fb.filebuffer[1] != 0x5A) {
		goto end_of_interaction;
	}
	else {
		this->e_lfanew = this->fb.filebuffer[startIndex] |
			(this->fb.filebuffer[startIndex + 1] << 8) |
			(this->fb.filebuffer[startIndex + 2] << 16) |
			(this->fb.filebuffer[startIndex + 3] << 24);

		if (e_lfanew > this->filesizeinBytes)
		{
			goto end_of_interaction;
		}
		if (this->fb.filebuffer[e_lfanew] != 0x50 || this->fb.filebuffer[e_lfanew + 1] != 0x45 || this->fb.filebuffer[e_lfanew + 2] != 0x00 || this->fb.filebuffer[e_lfanew + 3] != 0x00) {
			goto end_of_interaction;
		}
		this->filestate = this->fb.filebuffer[e_lfanew + 4] | this->fb.filebuffer[e_lfanew + 5] << 8;
		#ifdef _WIN64
		if (this->filestate != IMAGE_FILE_MACHINE_AMD64) {
			goto end_of_interaction;
		}
		#else
		if (this->filestate != IMAGE_FILE_MACHINE_I386) {
			goto end_of_interaction;
		}
		#endif
	}

	CloseHandle(hFile);
	return true;

	end_of_interaction:
	CloseHandle(hFile);
	throw invalid_argument("validation failed headers is not correct." + '\n');
}

PIMAGE_SECTION_HEADER MyLoadLibary::GetSectionTable(PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER pSectionTable = IMAGE_FIRST_SECTION(pNtHeaders);

	return pSectionTable;
}

void MyLoadLibary::MapSectionsToMemory() {
	this->num_of_sections = this->fb.filebuffer[e_lfanew + 6] | this->fb.filebuffer[e_lfanew + 7] << 8;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)this->fb.filebuffer + this->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionTable = IMAGE_FIRST_SECTION(pNtHeaders);
	try {
		this->memory_alloc = MemoryAlloc(VirtualAlloc((LPVOID)(pNtHeaders->OptionalHeader.ImageBase),
			pNtHeaders->OptionalHeader.SizeOfImage,
			MEM_RESERVE,
			PAGE_READWRITE));
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)this->fb.filebuffer + this->e_lfanew);
		if ((ULONGLONG)(this->memory_alloc.memory) != pNtHeaders->OptionalHeader.ImageBase) {
			throw invalid_argument("problem with virtual alloc");
		}
		for (int i = 0; i < this->num_of_sections; i++)
		{
			PIMAGE_SECTION_HEADER pCurrentSection = &pSectionTable[i];
			BYTE* pDestination = (BYTE*)this->memory_alloc.memory + pCurrentSection->VirtualAddress;
			BYTE* pSource = (BYTE*)this->fb.filebuffer + pCurrentSection->PointerToRawData;
			DWORD sizeToCopy = pCurrentSection->SizeOfRawData;
			LPVOID pCommittedMemory = VirtualAlloc(pDestination,
				pCurrentSection->Misc.VirtualSize,
				MEM_COMMIT,
				PAGE_READWRITE);
			if (pCommittedMemory == NULL) {
				throw runtime_error("VirtualAlloc(MEM_COMMIT) failed for a section.");
			}
			if (sizeToCopy > 0)
			{
				if (memcpy(pDestination, pSource, sizeToCopy) == NULL)
				{
					throw invalid_argument("memcpy didn't suceed");
				}
			}
		}
	}
	catch (const exception& e)
	{
		throw invalid_argument("VirtualAlloc(MEM_RESERVE) failed or was allocated at a different address.");
	}
}


bool MyLoadLibary::ResolveDependencies() {
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)this->fb.filebuffer + this->e_lfanew);
	DWORD rva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (rva == 0) {
		return true;
	}
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor =
		(PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)this->memory_alloc.memory + rva);
	while (pImportDescriptor->Name != 0)
	{
		char* dllname = (char*)((BYTE*)this->memory_alloc.memory + pImportDescriptor->Name);
		HMODULE hModule = LoadLibraryA(dllname);
		if (hModule == NULL) {
			throw runtime_error("Failed to load required DLL: " + string(dllname));
		}
		PIMAGE_THUNK_DATA pIAT =
			(PIMAGE_THUNK_DATA)((BYTE*)this->memory_alloc.memory + pImportDescriptor->FirstThunk);
		while (pIAT->u1.Function != 0)
		{
			FARPROC realFunctionAddress;
			if (IMAGE_SNAP_BY_ORDINAL(pIAT->u1.Ordinal))
			{
				DWORD ordinal = IMAGE_ORDINAL(pIAT->u1.Ordinal);
				realFunctionAddress = GetProcAddress(hModule, (LPCSTR)ordinal);
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImportByName =
					(PIMAGE_IMPORT_BY_NAME)((BYTE*)this->memory_alloc.memory + pIAT->u1.Function);
				const char* functionName = pImportByName->Name;
				realFunctionAddress = GetProcAddress(hModule, functionName);
			}
			if (realFunctionAddress == NULL) {
				throw runtime_error("Failed to get address for imported function.");
			}
			pIAT->u1.Function = (ULONGLONG)realFunctionAddress;
			pIAT++;
		}
		pImportDescriptor++;
	}
	return true;
}

bool MyLoadLibary::ExecuteEntryPoint() {
	return true;
}

/*
const wchar_t* MyLoadLibary::GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}
*/

/*
Your Load() function will call these in order.

bool ReadAndValidateHeaders()

Job: Opens the filename, reads the ent ire file into the pFileBuffer, and then parses that buffer to find and validate the PE headers (IMAGE_NT_HEADERS). It stores the pointer in pNtHeaders. If it's not a valid PE file, this returns false.

void MapSectionsToMemory()

Job: Allocates a block of memory using VirtualAlloc (and stores the pointer in pImageBase). It then loops through the PE file's section headers (using pNtHeaders) and copies each section (like .text, .data) from the pFileBuffer into the correct location in the new pImageBase memory block.

bool ResolveDependencies()

Job: Parses the DLL's import table. For every other DLL it needs (e.g., kernel32.dll), it calls the real LoadLibraryA. For every function it needs (e.g., CreateFileA), it calls the real GetProcAddress and writes the function's true address into the mapped DLL's Import Address Table (IAT).

bool ExecuteEntryPoint()

Job: This is the final step. It gets the address of the DLL's entry point (DllMain) from the PE headers. It then calls this function, passing it the pImageBase (the HMODULE) and the DLL_PROCESS_ATTACH reason code to let the DLL initialize itself.

Your public Load() function will be responsible for calling these functions one by one and checking for failure at each step.
*/


