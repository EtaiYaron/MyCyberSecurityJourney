#include "PortScanner.h"  
#include <string>  
#include <stdexcept>  
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <vector> 
#include <iostream>

#pragma comment(lib, "Ws2_32.lib") // Link with Ws2_32.lib 

using namespace std;  
const int MaxPort = 65535;  
const int MinPort = 1;  

PortScanner::PortScanner(string ip, int startport, int endport) {  
   if (startport < MinPort || endport < startport || endport > MaxPort)  
   {  
       throw invalid_argument("invalid input");  
   }
   int result = WSAStartup(MAKEWORD(2, 2), &this->wsaData);
   if (result != 0) {
       throw invalid_argument("WSAStartup failed");
   }
   this->ip = ip;  
   this->startport = startport;  
   this->endport = endport;
}  


PortScanner::PortScanner(string hostname){
    int result = WSAStartup(MAKEWORD(2, 2), &this->wsaData);
    if (result != 0) {
        throw invalid_argument("WSAStartup failed");
    }
    this->hostname = hostname;
}

PortScanner::PortScanner(string ip, int num) {
    int result = WSAStartup(MAKEWORD(2, 2), &this->wsaData);
    if (result != 0) {
        throw invalid_argument("WSAStartup failed");
    }
    this->ip = ip;
}

string PortScanner::ScanPorts() {  
    string res = "";
    
    const char* ipadrr = this->ip.c_str();
    for (size_t i = this->startport; i <= this->endport; i++)
    {
        SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(i); 
        inet_pton(AF_INET, this->ip.c_str(), &(serverAddr.sin_addr)); 
        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR) {
            res += ", " + to_string(i);
        }
        closesocket(clientSocket);
            
    }
    
    if (res.empty()) {
        return "the ports which open are: none";
    }
    else {
        return "the ports which open are:" + res.substr(1); 
    }
    
}


vector<string>* PortScanner::ScanPorts(vector<string> popularports) {
    vector<string>* res = new vector<string>();

    for (string port : popularports) {
        SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }
        DWORD timeout = 2000;
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(atoi(port.c_str()));
        inet_pton(AF_INET, this->ip.c_str(), &(serverAddr.sin_addr));
        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR) {
            res->push_back(port);
        }
        closesocket(clientSocket);
    }

    return res;
}

string PortScanner::ResolveHosttoIP() {
    struct addrinfo hints, * result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM; 

    const char* hostname = this->hostname.c_str();
    int s = getaddrinfo(hostname, NULL, &hints, &result);
    if (s != 0) {
        string output(gai_strerrorA(s));
        throw invalid_argument("getadrrinfo returned: " + output);           
    }

    string retval = "";
    int cnt = 1;
    for (struct addrinfo* rp = result; rp != NULL; rp = rp->ai_next) {
        
        char ipstr[INET_ADDRSTRLEN];
        struct sockaddr_in* ipv4 = (struct sockaddr_in*)rp->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
        
        string var(ipstr);
        retval = "The " + to_string(cnt) + " ip adress is: " + var + ".\n";
        cnt++;
    }
    return retval;
}

string PortScanner::ResolveIPtoHost(vector<string> popularports) {
    vector<string>* openports = this->ScanPorts(popularports);
    struct sockaddr_in saGNI;
    char hostname[NI_MAXHOST];
    char servInfo[NI_MAXSERV];
    u_short port;
    DWORD dwRetval;

    saGNI.sin_family = AF_INET;
    inet_pton(AF_INET, this->ip.c_str(), &(saGNI.sin_addr));

    for (string port : *openports) {
        saGNI.sin_port = htons(atoi(port.c_str()));
        dwRetval = getnameinfo((struct sockaddr*)&saGNI,
            sizeof(struct sockaddr),
            hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, 0); 

        if (dwRetval != 0) {
            continue;
        }
        else {
            std::string hoststr(hostname);
            if (hoststr == this->ip) continue;
            delete(openports);
            return hostname;
        }
    }
    delete(openports);
    throw invalid_argument("there is no match for host name to this ip address");
}

PortScanner::~PortScanner() {
    WSACleanup();
}

