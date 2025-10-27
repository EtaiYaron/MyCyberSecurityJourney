#include "MyLoadLibary.h"
#include <stdexcept>  
#include <memory>
#pragma once

# define minbufsize 62
# define startIndex 0x3C

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

	if (this->filesizeinBytes < minbufsize || this->fb.filebuffer[0] != 0x4D || this->fb.filebuffer[1] != 0x5A ) {
		goto end_of_interaction;
	}
	else {
		uint32_t e_lfanew = this->fb.filebuffer[startIndex] |
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

		WORD filestate = this->fb.filebuffer[e_lfanew + 4] | this->fb.filebuffer[e_lfanew + 5] << 8;
	}



end_of_interaction:
	CloseHandle(hFile);
	throw invalid_argument("validation failed headers is not correct." + '\n');
	return true;
}

void MyLoadLibary::MapSectionsToMemory() {

}
bool MyLoadLibary::HandleRelocations() {
	return true;
}
bool MyLoadLibary::ResolveDependencies() {
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

Job: Opens the filename, reads the entire file into the pFileBuffer, and then parses that buffer to find and validate the PE headers (IMAGE_NT_HEADERS). It stores the pointer in pNtHeaders. If it's not a valid PE file, this returns false.

void MapSectionsToMemory()

Job: Allocates a block of memory using VirtualAlloc (and stores the pointer in pImageBase). It then loops through the PE file's section headers (using pNtHeaders) and copies each section (like .text, .data) from the pFileBuffer into the correct location in the new pImageBase memory block.

bool HandleRelocations()

Job: Checks if the DLL was loaded at its preferred ImageBase. If not, it must parse the DLL's relocation table (the .reloc section) and "fix" all hardcoded addresses inside the newly mapped code to point to the correct new locations.

bool ResolveDependencies()

Job: Parses the DLL's import table. For every other DLL it needs (e.g., kernel32.dll), it calls the real LoadLibraryA. For every function it needs (e.g., CreateFileA), it calls the real GetProcAddress and writes the function's true address into the mapped DLL's Import Address Table (IAT).

bool ExecuteEntryPoint()

Job: This is the final step. It gets the address of the DLL's entry point (DllMain) from the PE headers. It then calls this function, passing it the pImageBase (the HMODULE) and the DLL_PROCESS_ATTACH reason code to let the DLL initialize itself.

Your public Load() function will be responsible for calling these functions one by one and checking for failure at each step.
*/


