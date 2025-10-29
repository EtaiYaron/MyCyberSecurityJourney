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



