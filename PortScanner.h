#pragma once
#include <string>
#include <vector>
#include <WinSock2.h>

using namespace std;

class PortScanner {
private:
	string ip;
	int startport;
	int endport;
	WSADATA wsaData;
	string hostname;
	
public:
	PortScanner(string, int , int );
	PortScanner(string );
	PortScanner(string , int );
	string ScanPorts();
	vector<string>* ScanPorts(vector<string> );
	string ResolveHosttoIP();
	string ResolveIPtoHost(vector<string> );
	~PortScanner();

};