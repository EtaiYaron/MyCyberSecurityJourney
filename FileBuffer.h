#include <Windows.h>
#pragma once



class FileBuffer{
public:
	FileBuffer();
	FileBuffer(DWORD);
	BYTE* GetFileBuffer();
	~FileBuffer();
	BYTE* filebuffer;
	
};

FileBuffer::FileBuffer(DWORD size) {
	this->filebuffer = NULL;
}
FileBuffer::FileBuffer(DWORD size) {
	this->filebuffer = new BYTE[size];
}
FileBuffer::~FileBuffer() {
	delete[](this->filebuffer);
}

