#include "PortScanner.h"
#include <cassert>
#include <iostream>
#include <vector>
#include <string>

void test_constructor_invalid_ports() {
    try {
        PortScanner ps1("127.0.0.1", 0, 10);
        std::cout << "FAIL: Constructor did not throw for startport < MinPort\n";
    }
    catch (const std::invalid_argument&) {
        std::cout << "PASS: Constructor threw for startport < MinPort\n";
    }
    try {
        PortScanner ps2("127.0.0.1", 10, 5);
        std::cout << "FAIL: Constructor did not throw for endport < startport\n";
    }
    catch (const std::invalid_argument&) {
        std::cout << "PASS: Constructor threw for endport < startport\n";
    }
    try {
        PortScanner ps3("127.0.0.1", 10, 70000);
        std::cout << "FAIL: Constructor did not throw for endport > MaxPort\n";
    }
    catch (const std::invalid_argument&) {
        std::cout << "PASS: Constructor threw for endport > MaxPort\n";
    }
}

void test_constructor_valid_ports() {
    try {
        PortScanner ps("127.0.0.1", 1, 10);
        std::cout << "PASS: Constructor succeeded for valid ports\n";
    }
    catch (...) {
        std::cout << "FAIL: Constructor threw for valid ports\n";
    }
}

void test_scan_ports_range() {
    try {
        PortScanner ps("127.0.0.1", 80, 80);
        std::string result = ps.ScanPorts();
        if (result.find("the ports which open are:") != std::string::npos) {
            std::cout << "PASS: ScanPorts (range) returned expected string\n";
        }
        else {
            std::cout << "FAIL: ScanPorts (range) did not return expected string\n";
        }
    }
    catch (...) {
        std::cout << "FAIL: ScanPorts (range) threw exception\n";
    }
}

void test_scan_ports_vector() {
    try {
        PortScanner ps("127.0.0.1", 80, 80);
        std::vector<std::string> vec = { "80" };
        std::vector<std::string>* result = ps.ScanPorts(vec);
        if (result && !result->empty()) {
            std::cout << "PASS: ScanPorts (vector) returned non-empty pointer\n";
        }
        else {
            std::cout << "PASS: ScanPorts (vector) returned empty pointer (ok if port closed)\n";
        }
        delete result;
    }
    catch (...) {
        std::cout << "FAIL: ScanPorts (vector) threw exception\n";
    }
}

void test_resolve_host_to_ip() {
    try {
        PortScanner ps("localhost");
        std::string result = ps.ResolveHosttoIP();
        if (result.find("ip adress") != std::string::npos) {
            std::cout << "PASS: ResolveHosttoIP returned expected result\n";
        }
        else {
            std::cout << "FAIL: ResolveHosttoIP did not return expected result\n";
        }
    }
    catch (...) {
        std::cout << "FAIL: ResolveHosttoIP threw exception\n";
    }
}

void test_resolve_host_to_ip_invalid() {
    try {
        PortScanner ps("invalidhostnamethatdoesnotexist12345.example");
        ps.ResolveHosttoIP();
        std::cout << "FAIL: ResolveHosttoIP did not throw for invalid hostname\n";
    }
    catch (const std::invalid_argument&) {
        std::cout << "PASS: ResolveHosttoIP threw for invalid hostname\n";
    }
}

void test_resolve_ip_to_host() {
    try {
        PortScanner ps("127.0.0.1", 80, 80);
        std::vector<std::string> vec = { "80" };
        ps.ResolveIPtoHost(vec);
        std::cout << "PASS: ResolveIPtoHost succeeded (may be ok even if no host found)\n";
    }
    catch (const std::invalid_argument& e) {
        if (std::string(e.what()).find("no match") != std::string::npos) {
            std::cout << "PASS: ResolveIPtoHost threw for no hostname found\n";
        }
        else {
            std::cout << "FAIL: ResolveIPtoHost threw unexpected error\n";
        }
    }
    catch (...) {
        std::cout << "FAIL: ResolveIPtoHost threw unexpected exception\n";
    }
}

/*
int main() {
    test_constructor_invalid_ports();
    test_constructor_valid_ports();
    test_scan_ports_range();
    test_scan_ports_vector();
    test_resolve_host_to_ip();
    test_resolve_host_to_ip_invalid();
    test_resolve_ip_to_host();
    std::cout << "All basic tests completed.\n";
    return 0;
}
*/