#pragma once

#include <windows.h>

class FileBuffer {
public:
    BYTE* filebuffer;
    DWORD filesize;

    FileBuffer();

    FileBuffer(DWORD size);

    ~FileBuffer();

    FileBuffer(const FileBuffer& other);

    FileBuffer& operator=(const FileBuffer& other);

    FileBuffer(FileBuffer&& other) noexcept;

    FileBuffer& operator=(FileBuffer&& other) noexcept;
};



