#include "PortScanner.h"  
#include <string>  
#include <stdexcept>  
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <vector> 
#include <iostream>
#include <thread>

#pragma comment(lib, "Ws2_32.lib") // Link with Ws2_32.lib 

using namespace std;
const int MaxPort = 65535;
const int MinPort = 1;



PortScanner::PortScanner(string hostname) {
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

string PortScanner::ScanPorts(int startport, int endport) {

    if (startport < MinPort || endport < startport || endport > MaxPort)
    {
        throw invalid_argument("invalid input");
    }
    string res = "";
    vector<string> ports;
    for (int i = startport; i <= endport; i++)
    {
        ports.push_back(to_string(i));
    }
    vector<string>* openports = this->ScanPorts(ports);
    for (string port : *openports) {
        res += ", " + port;
    }
    delete(openports);
    if (res.empty()) {
        return "the ports which open are: none";
    }
    else {
        return "the ports which open are:" + res.substr(1);
    }

    /*DWORD numProcessors = 0;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    numProcessors = sysInfo.dwNumberOfProcessors;
    int* ptr;
    ptr = (int*)malloc(numProcessors * sizeof(int));
    if (ptr == NULL) {

        throw invalid_argument("Memory allocation failed!\n");
    }
    for (int i = 0; i < numProcessors; i++) {
        if (i == 0)
        {
            ptr[i] = startport;
        }
        else if(i != numProcessors -1){
            ptr[i] = ptr[i - 1] + (static_cast<int>((endport - startport) / numProcessors) * i);
        }
    }

    vector<thread> threads;
    vector<string> thread_results(numProcessors);

    for (int i = 0; i < numProcessors; i++)
    {
        threads.emplace_back([this, &thread_results, i, ptr, endport, numProcessors]() {
            if (i == numProcessors - 1)
                thread_results[i] = this->ScanPortsInternal(ptr[i], endport);
            else
                thread_results[i] = this->ScanPortsInternal(ptr[i], ptr[i + 1]-1);
            });
    }

    for (int i = 0; i < numProcessors; i++)
    {
        threads[i].join();
    }
    for (string x : thread_results) {
        res +=  "," + x;
    }

    free(ptr);

    if (res.empty()) {
        return "the ports which open are: none";
    }
    else {
        return "the ports which open are:" + res.substr(1);
    }  */
}

//string PortScanner::ScanPortsInternal(int startport, int endport) {
//    if (startport < MinPort || endport < startport || endport > MaxPort)
//    {
//        throw invalid_argument("invalid input");
//    }
//    string res = "";
//
//
//    const char* ipadrr = this->ip.c_str();
//    for (size_t i = startport; i <= endport; i++)
//    {
//        SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//        if (clientSocket == INVALID_SOCKET) {
//            continue;
//        }
//        sockaddr_in serverAddr;
//        serverAddr.sin_family = AF_INET;
//        serverAddr.sin_port = htons(i);
//        inet_pton(AF_INET, this->ip.c_str(), &(serverAddr.sin_addr));
//        if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR) {
//            res += ", " + to_string(i);
//        }
//        closesocket(clientSocket);
//
//    }
//    if (res.empty())
//    {
//        return res;
//    }
//    return res.substr(1);
//}


vector<string>* PortScanner::ScanPorts(vector<string> popularports) {
    string res = "";

    DWORD numProcessors = 0;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    numProcessors = sysInfo.dwNumberOfProcessors;
    vector<vector<string>> dividedports;
    for (int i = 0; i < numProcessors; i++)
    {
        vector<string> v;
        dividedports.push_back(v);
    }
    for (int i = 0; i < popularports.size(); i++)
    {
        dividedports[i % numProcessors].push_back(popularports[i]);
    }

    vector<thread> threads;
    vector<vector<string>*> thread_results(numProcessors);

    for (int i = 0; i < numProcessors; i++)
    {
        threads.emplace_back([this, &thread_results, i, dividedports]() {
            thread_results[i] = this->ScanPortsInternal(dividedports[i]);
            });
    }
    for (int i = 0; i < numProcessors; i++)
    {
        threads[i].join();
    }
    vector<string>* v = new vector<string>();
    for (vector<string>* x : thread_results) {
        for (string str : *x) {
            v->push_back(str);
        }
    }
    return v;
}

vector<string>* PortScanner::ScanPortsInternal(vector<string> popularports) {
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



