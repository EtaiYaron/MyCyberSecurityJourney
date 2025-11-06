#include "FileBuffer.h"
#include <windows.h> 
#include <algorithm> 

FileBuffer::FileBuffer(){
    this->filebuffer = nullptr;
    this->filesize = 0;
}

FileBuffer::FileBuffer(DWORD size){
    this->filebuffer = new BYTE[size];
    this->filesize = size;
}

FileBuffer::~FileBuffer() {
    delete[] this->filebuffer;
}


FileBuffer::FileBuffer(const FileBuffer& other) {
    this->filesize = other.filesize;
    this->filebuffer = new BYTE[this->filesize];
    memcpy(this->filebuffer, other.filebuffer, this->filesize);
}

FileBuffer& FileBuffer::operator=(const FileBuffer& other) {
    if (this == &other) {
        return *this; 
    }

    delete[] this->filebuffer;

    this->filesize = other.filesize;
    this->filebuffer = new BYTE[this->filesize];
    memcpy(this->filebuffer, other.filebuffer, this->filesize);
    return *this;
}


FileBuffer::FileBuffer(FileBuffer&& other) noexcept{
    this->filebuffer = nullptr;
    this->filesize = 0;

    this->filebuffer = other.filebuffer;
    this->filesize = other.filesize;

    other.filebuffer = nullptr;
    other.filesize = 0;
}

FileBuffer& FileBuffer::operator=(FileBuffer&& other) noexcept {
    if (this == &other) {
        return *this; 
    }

    delete[] this->filebuffer;

    this->filebuffer = other.filebuffer;
    this->filesize = other.filesize;

    other.filebuffer = nullptr;
    other.filesize = 0;

    return *this;
}