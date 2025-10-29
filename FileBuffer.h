#pragma once
#include <Windows.h>




class FileBuffer{
public:
	FileBuffer();
	FileBuffer(DWORD);
	BYTE* GetFileBuffer();
	~FileBuffer();
	BYTE* filebuffer;
	
};



