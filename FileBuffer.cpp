#include "FileBuffer.h"



FileBuffer::FileBuffer(DWORD size) {
	this->filebuffer = new BYTE[size];
}
FileBuffer::~FileBuffer() {
	delete[](this->filebuffer);
}