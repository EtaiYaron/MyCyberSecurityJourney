#include "MyLoadLibary.h"
#include <stdexcept>
#include <memory>
#include <memory.h>
#include <vector>
#include <iostream>
#include <string>

#pragma once

#define minbufsize 62
#define startIndex 0x3C

using namespace std;



MyLoadLibary::MyLoadLibary(string filename) {
    this->filename = filename;
    this->filesizeinBytes = 0;
    this->e_lfanew = 0;
    this->filestate = 0;
    this->num_of_sections = 0;
}

bool MyLoadLibary::Load() {
    try
    {
        cout << "calling: ReadAndValidateHeaders" << endl;
        this->ReadAndValidateHeaders();
        cout << "ReadAndValidateHeaders pass" << endl;

        cout << "calling: MapSectionsToMemory" << endl;
        this->MapSectionsToMemory();
        cout << "MapSectionsToMemory pass" << endl;

        cout << "calling: ResolveDependencies" << endl;
        this->ResolveDependencies();
        cout << "ResolveDependencies pass" << endl;

        // *** NEW STEP ***
        // Apply final memory permissions (e.g., set .text to Executable)
        // This fixes the 0xc0000005 crash in DllMain.
        cout << "calling: SetMemoryProtections" << endl;
        this->SetMemoryProtections();
        cout << "SetMemoryProtections pass" << endl;

        cout << "calling: ExecuteEntryPoint" << endl;
        bool result = this->ExecuteEntryPoint();
        cout << "ExecuteEntryPoint pass" << endl;

        return result;
    }
    catch (const exception& e)
    {
        cout << "MyLoadLibary::Load() FAILED: " << e.what() << endl;
        throw;
    }
}

void MyLoadLibary::ReadAndValidateHeaders() {
    HANDLE hFile = INVALID_HANDLE_VALUE;
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
        DWORD error = GetLastError();
        throw invalid_argument("Terminal failure: unable to open file for read. Error code: " + to_string(error) + "\n");
    }

    LARGE_INTEGER numofBytes;
    if (0 == GetFileSizeEx(hFile, &numofBytes)) {
        CloseHandle(hFile);
        throw invalid_argument("Terminal failure: " + to_string(GetLastError()) + '\n');
    }
    if (numofBytes.QuadPart > MAXDWORD) {
        CloseHandle(hFile);
        throw invalid_argument("file is to big.");
    }
    this->filesizeinBytes = (DWORD)numofBytes.QuadPart;

    // This is safe now because your FileBuffer class is correct
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
    return;

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

    DWORD sizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;

    DWORD saneLimit = this->filesizeinBytes + (20 * 1024 * 1024);

    if (sizeOfImage == 0 || sizeOfImage > saneLimit) {
        throw runtime_error("File is corrupt: Invalid SizeOfImage (0 or too large).");
    }
    if (sizeOfHeaders == 0 || sizeOfHeaders > sizeOfImage) {
        throw runtime_error("File is corrupt: Invalid SizeOfHeaders (0 or > SizeOfImage).");
    }

    if (this->num_of_sections > 0 && sizeOfHeaders > pSectionTable[0].VirtualAddress) {
        throw runtime_error("File is corrupt: SizeOfHeaders overlaps first section.");
    }


    cout << "calling MemoryAlloc \n";
    try {
        this->memory_alloc = MemoryAlloc(VirtualAlloc((LPVOID)(pNtHeaders->OptionalHeader.ImageBase),
            sizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE));
        cout << "MemoryAlloc finished \n";
    }
    catch (const exception& e)
    {
        throw invalid_argument("VirtualAlloc(MEM_RESERVE) failed or was allocated at a different address.");
    }

    if (this->memory_alloc.memory == NULL)
    {
        DWORD error = GetLastError();
        throw runtime_error("VirtualAlloc failed to get preferred ImageBase. Error: " + to_string(error));
    }

    if ((ULONGLONG)(this->memory_alloc.memory) != pNtHeaders->OptionalHeader.ImageBase) {
        throw runtime_error("VirtualAlloc failed: Did not return preferred ImageBase.");
    }
    DWORD headersToCopy = min(sizeOfHeaders, this->filesizeinBytes);
    memcpy(this->memory_alloc.memory,
        this->fb.filebuffer,
        headersToCopy);
    cout << "i am here \n";
    for (int i = 0; i < this->num_of_sections; i++)
    {

        PIMAGE_SECTION_HEADER pCurrentSection = &pSectionTable[i];

        if (pCurrentSection->Misc.VirtualSize == 0)
        {
            continue;
        }

        if (pCurrentSection->VirtualAddress == 0 || (pCurrentSection->VirtualAddress + pCurrentSection->Misc.VirtualSize) > sizeOfImage) {
            cout << "Warning: Skipping corrupt section header." << endl;
            continue;
        }

        BYTE* pDestination = (BYTE*)this->memory_alloc.memory + pCurrentSection->VirtualAddress;
        BYTE* pSource = (BYTE*)this->fb.filebuffer + pCurrentSection->PointerToRawData;
        DWORD sizeToCopy = pCurrentSection->SizeOfRawData;

        // *** THIS IS THE FIX FOR THE SKIPPED MEMCPY ***
        if (sizeToCopy > 0)
        {
            DWORD realSizeToCopy = min(sizeToCopy, pCurrentSection->Misc.VirtualSize);

            if (pCurrentSection->PointerToRawData < this->filesizeinBytes)
            {
                DWORD availableBytesInFile = this->filesizeinBytes - pCurrentSection->PointerToRawData;
                realSizeToCopy = min(realSizeToCopy, availableBytesInFile);

                memcpy(pDestination, pSource, realSizeToCopy);
            }
        }
    }
}


void MyLoadLibary::ResolveDependencies() {
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)this->fb.filebuffer + this->e_lfanew);
    DWORD rva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD size = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    DWORD sizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;

    if (rva == 0) {
        cout << "No Import Table found (rva is 0). Skipping." << endl;
        return;
    }
    if (rva >= sizeOfImage)
    {
        cout << "Error: Import Table RVA is outside the image bounds. File is corrupt." << endl;
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)this->memory_alloc.memory + rva);
    cout << "Entering the pImportDescriptor->Name != 0 while \n";

    while (pImportDescriptor->Name != 0 && (BYTE*)pImportDescriptor < ((BYTE*)this->memory_alloc.memory + sizeOfImage))
    {
        cout << "in the pImportDescriptor->Name != 0 while \n";
        char* dllname;
        HMODULE hModule;
        if (pImportDescriptor->Name == 0 || pImportDescriptor->Name >= sizeOfImage) {
            cout << "Corrupt Import Descriptor Name RVA. Skipping." << endl;
            goto keep_while;
        }

        dllname = (char*)((BYTE*)this->memory_alloc.memory + pImportDescriptor->Name);
        cout << "calling to LoadLibraryA(dllname) \n";
        hModule = LoadLibraryA(dllname);
        cout << "finished with LoadLibraryA(dllname) \n";
        if (hModule == NULL) {
            cout << "Warning: Could not load dependent DLL: " << dllname << endl;
            goto keep_while;
        }
        else {
            if (pImportDescriptor->FirstThunk == 0 || pImportDescriptor->FirstThunk >= sizeOfImage) {
                cout << "Corrupt FirstThunk RVA. Skipping." << endl;
                goto keep_while;
            }

            PIMAGE_THUNK_DATA pIAT =
                (PIMAGE_THUNK_DATA)((BYTE*)this->memory_alloc.memory + pImportDescriptor->FirstThunk);

            PIMAGE_THUNK_DATA pThunk = NULL;
            if (pImportDescriptor->OriginalFirstThunk != 0) {
                pThunk = (PIMAGE_THUNK_DATA)((BYTE*)this->memory_alloc.memory + pImportDescriptor->OriginalFirstThunk);
            }
            else {
                pThunk = pIAT;
            }

            // *** THIS IS THE FIX FOR THE SKIPPED LOOP ***
            cout << "entering the pThunk->u1.Function != 0 while \n";
            while (pThunk->u1.Function != 0)
            {
                FARPROC realFunctionAddress;

                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
                {
                    DWORD ordinal = IMAGE_ORDINAL(pThunk->u1.Ordinal);
                    realFunctionAddress = GetProcAddress(hModule, (LPCSTR)ordinal);
                }
                else
                {
                    if (pThunk->u1.Function >= sizeOfImage) {
                        cout << "Error: Corrupt Import By Name RVA. Skipping function." << endl;
                        goto keep_while2;
                    }

                    PIMAGE_IMPORT_BY_NAME pImportByName =
                        (PIMAGE_IMPORT_BY_NAME)((BYTE*)this->memory_alloc.memory + pThunk->u1.Function);

                    if ((BYTE*)pImportByName >= ((BYTE*)this->memory_alloc.memory + sizeOfImage)) {
                        cout << "Error: Corrupt Import By Name pointer. Skipping function." << endl;
                        goto keep_while2;
                    }

                    const char* functionName = pImportByName->Name;
                    realFunctionAddress = GetProcAddress(hModule, functionName);
                }
                if (realFunctionAddress == NULL) {
                    goto keep_while2;
                }

                pIAT->u1.Function = (ULONGLONG)realFunctionAddress;

            keep_while2:
                pIAT++;
                pThunk++;
            }
            cout << "exiting the pThunk->u1.Function != 0 while: \n";
        }
    keep_while:
        pImportDescriptor++;
    }
    cout << "exiting the pImportDescriptor->Name != 0 while: \n";
    return;
}

// *** THIS IS THE NEW FUNCTION TO FIX THE 0xc0000005 CRASH ***
void MyLoadLibary::SetMemoryProtections() {
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)this->fb.filebuffer + this->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionTable = IMAGE_FIRST_SECTION(pNtHeaders);
    DWORD oldProtect = 0;

    // First, set the headers to Read-Only
    VirtualProtect(this->memory_alloc.memory, pNtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    // Loop through all sections and apply their correct permissions
    for (int i = 0; i < this->num_of_sections; i++)
    {
        PIMAGE_SECTION_HEADER pCurrentSection = &pSectionTable[i];

        if (pCurrentSection->Misc.VirtualSize == 0) {
            continue;
        }

        BYTE* pDestination = (BYTE*)this->memory_alloc.memory + pCurrentSection->VirtualAddress;
        DWORD characteristics = pCurrentSection->Characteristics;

        DWORD newProtect = PAGE_READONLY; // Default

        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                newProtect = PAGE_EXECUTE_READWRITE;
            }
            else if (characteristics & IMAGE_SCN_MEM_READ) {
                newProtect = PAGE_EXECUTE_READ;
            }
            else {
                newProtect = PAGE_EXECUTE;
            }
        }
        else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            newProtect = PAGE_READWRITE;
        }
        else if (characteristics & IMAGE_SCN_MEM_READ) {
            newProtect = PAGE_READONLY;
        }

        if (characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
            newProtect |= PAGE_NOCACHE;
        }

        if (!VirtualProtect(pDestination, pCurrentSection->Misc.VirtualSize, newProtect, &oldProtect)) {
            // This could fail, but we'll just log it.
            cout << "Warning: VirtualProtect failed for a section." << endl;
        }
    }
}


bool MyLoadLibary::ExecuteEntryPoint() {
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)this->fb.filebuffer + this->e_lfanew);
    DWORD rva = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    if (rva == 0)
    {
        cout << "No entry point found. Skipping." << endl;
        return true;
    }

    DWORD sizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    if (rva >= sizeOfImage) {
        cout << "Error: Entry Point RVA is outside image bounds. Cannot execute." << endl;
        return false;
    }

    BYTE* pointertoentrypoint = (BYTE*)this->memory_alloc.memory + rva;
    typedef BOOL(WINAPI* pDllMain)(HMODULE, DWORD, LPVOID);
    pDllMain entryPointFunction = (pDllMain)pointertoentrypoint;

    cout << "Calling DllMain at " << (void*)pointertoentrypoint << "..." << endl;

    BOOL result = entryPointFunction(
        (HMODULE)this->memory_alloc.memory,
        DLL_PROCESS_ATTACH,
        NULL
    );

    cout << "DllMain returned: " << (result ? "TRUE" : "FALSE") << endl;
    return result;
}