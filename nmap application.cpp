#include <iostream>
#include <iomanip>
#include <regex>
#include <string> 
#include <stdlib.h>
#include "PortScanner.h"
#include "Response.h"
#include <climits>
#include "OpenForPersistence.h"
using namespace std;

int nmapmenu();

int main(){
    
    //OpenForPersistence* f = new OpenForPersistence();
    //delete(f);
    return nmapmenu();
}


int nmapmenu()
{
    
   cout << "Hello, welcome to my port scanner.\n";
   int num = 0;
   do {
       cout << "Which service is required? \nclick 1 for port mapping click 2 for Hostname to IP Address and click 3 for IP Address to Hostname.\n";
       cin >> num;
       cin.ignore(INT_MAX, '\n');
   } while (num < 1 || num > 3);

   char* dynamicBuffer = (char*)calloc(100, sizeof(char));
   if (dynamicBuffer == NULL) {
       cout << "Memory allocation failed!" << endl;
       return 0;
   }
   
   if (num == 1) {
       cout << "please give me the target ip, the start port and the end port in this format: ";
       cout << "scanner <ip adress> --start <port> --end <port> \n";

       cin.getline(dynamicBuffer, 100);
       string input(dynamicBuffer);
       input.erase(input.begin(), std::find_if(input.begin(), input.end(), [](unsigned char ch) {
           return !std::isspace(ch);
           }));
       regex pattern(R"(^scanner\s+((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\s+--start\s+(\d{1,5})\s+--end\s+(\d{1,5})$)");
       smatch matches;

       if (regex_match(input, matches, pattern)) {
           string ip = matches[1];
           string start_port = matches[2];
           string end_port = matches[3];

           int start_port1 = atoi(start_port.c_str());
           int end_port1 = atoi(end_port.c_str());
           PortScanner* p;
           Response<string>* r;
           try {
               PortScanner* p = new PortScanner(ip, 0);
               
               try
               {
                   cout << "starting scan ports \n";
                   r = new Response<string>("", p->ScanPorts(start_port1, end_port1));

                   cout << r->getReturnValue();

               }
               catch (const exception& e)
               {
                   r = new Response<string>(e.what());
                   cout << r->getErrorMessage();
               }
               delete(r);
               delete(p);
               goto end_iteraction;
           }
           catch (const exception& e) {
               r = new Response<string>(e.what());
               cout << r->getErrorMessage();
               delete(r);
               goto end_iteraction;
           }
       }
       else {
           cout<<"format isn't valid" << endl;
           goto end_iteraction;
       }
       
   }
   else {
       

       vector<string> popularports = {
           "21",    // FTP
           "22",    // SSH
           "23",    // Telnet
           "80",    // HTTP
           "53",    // DNS
           "443",   // HTTPS
           "8080",  // HTTP Alternate
           "8443"   // HTTPS Alternate
       };

       if (num == 2) {
           
           cout << "please give me the host name in this format: ";
           cout << "scanner <hostname> \n";
           cin.getline(dynamicBuffer, 100);
           string input(dynamicBuffer);
           regex pattern(R"(^scanner\s+([^\s]+)$)");
           smatch matches;

           if (regex_match(input, matches, pattern)) {
              string hostname = matches[1];
              PortScanner* p;
              Response<string>* r;
              try {
                  p = new PortScanner(hostname);
                  try {
                      string retval = p->ResolveHosttoIP();
                      r = new Response<string>("", retval);
                      cout << r->getReturnValue();
                  }
                  catch (const exception& e)
                  {
                      r = new Response<string>(e.what());
                      cout << r->getErrorMessage();
                  }
                  delete(r);
                  delete(p);
                  goto end_iteraction;
              }
              catch (const exception& e)
              {
                r = new Response<string>(e.what());
                cout << r->getErrorMessage();
              }
               delete(r);
               goto end_iteraction;              
           }
           else {
               cout << "Input format is invalid." << endl;
               goto end_iteraction;
           }


       }
       else {
           cout << "please give me the target ip, the start port the end port and the number of threads in this format: ";
           cout << " scanner <ip adress>\n";

      
           cin.getline(dynamicBuffer, 100);
           string input(dynamicBuffer);
           regex pattern(R"(^\s*scanner\s+((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\s*$)");
           smatch matches;

           if (regex_match(input, matches, pattern)) {
               string ip = matches[1];
               PortScanner* p;
               Response<string>* r;
               try {
                   p = new PortScanner(ip, 0);
                   try {
                       cout << "trying to find host name based on ip. \n";
                       string retval = p->ResolveIPtoHost(popularports);
                       r = new Response<string>("", retval);
                       cout << r->getReturnValue();
                   }
                   catch (const exception& e)
                   {
                       cout << "wait, an error occured. \n";
                       r = new Response<string>(e.what());
                       cout << r->getErrorMessage();

                   }
                   delete(r);
                   delete(p);
                   goto end_iteraction;
               }
               catch(const exception& e)
               {
                   r = new Response<string>(e.what());
                   cout << r->getErrorMessage();

               }
               delete(r);
               goto end_iteraction;
           }
           else {
               cout << "Input format is invalid." << endl;
               goto end_iteraction;
           }

       }
       
   }
   end_iteraction:
   cout << "\n thanks for using my scanner.";
   free(dynamicBuffer);
   return 0;
}
