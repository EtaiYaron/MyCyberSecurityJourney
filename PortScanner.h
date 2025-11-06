#pragma once
#include <string>
#include <vector>
#include <WinSock2.h>

using namespace std;

class PortScanner {
private:
	string ip;
	WSADATA wsaData;
	string hostname;
	//string ScanPortsInternal(int, int);
	vector<string>* ScanPortsInternal(vector<string>);
public:
	PortScanner(string );
	PortScanner(string , int );
	
	string ScanPorts(int, int);
	vector<string>* ScanPorts(vector<string> );
	string ResolveHosttoIP();
	string ResolveIPtoHost(vector<string> );
	~PortScanner();

};