#pragma once

#include <windows.h> 
#include <chrono>    
#include <thread> 
#include <iostream>


using namespace std;

class OpenForPersistence
{
public:
	OpenForPersistence();
private:

};

OpenForPersistence::OpenForPersistence() {
    this_thread::sleep_for(std::chrono::seconds(5));
    HMODULE hModule = LoadLibraryA("non_existent_plugin.dll");
    FreeLibrary(hModule);

}