#include <iostream>
#include <iomanip>

#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

std::string GetStateString(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED:
        return "CLOSED";
    case MIB_TCP_STATE_LISTEN:
        return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT:
        return "SYN-SENT";
    case MIB_TCP_STATE_SYN_RCVD:
        return "SYN-RECEIVED";
    case MIB_TCP_STATE_ESTAB:
        return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:
        return "FIN-WAIT-1";
    case MIB_TCP_STATE_FIN_WAIT2:
        return "FIN-WAIT-2";
    case MIB_TCP_STATE_CLOSE_WAIT:
        return "CLOSE-WAIT";
    case MIB_TCP_STATE_CLOSING:
        return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:
        return "LAST-ACK";
    case MIB_TCP_STATE_TIME_WAIT:
        return "TIME-WAIT";
    default:
        return "UNKNOWN";
    }
}



void PrintSocketInfo(MIB_TCPTABLE_OWNER_PID* pTcpTable) {
    std::vector<std::string> processNames;

    // Collect process names
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];

        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
        if (hProcess != nullptr) {
            char processName[MAX_PATH];
            DWORD size = sizeof(processName);
            if (QueryFullProcessImageNameA(hProcess, 0, processName, &size) != 0) {
                processNames.push_back(processName);
            }
            CloseHandle(hProcess);
        }
    }

    // Find the maximum length of process names
    size_t maxProcessNameLength = 0;
    for (const std::string& name : processNames) {
        maxProcessNameLength = max(maxProcessNameLength, name.size());
    }

    std::string separatorLine(maxProcessNameLength + maxProcessNameLength * 0.9, '=');
    std::cout << std::noshowpos;
    // Print socket information
    std::cout << std::setw(14) << "Process ID" << std::setw(maxProcessNameLength + 2) << "Process Name" << std::setw(24) 
        << "Local Address"<< "  Port" << std::setw(25) << "Remote Address" << "  Port"
        << std::setw(10) << "Protocol" << std::setw(16) << "State\n";
    std::cout << separatorLine << std::endl;

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID row = pTcpTable->table[i];

        char localAddrStr[INET_ADDRSTRLEN];
        char remoteAddrStr[INET_ADDRSTRLEN];

        // Convert addresses to string format
        inet_ntop(AF_INET, &(row.dwLocalAddr), localAddrStr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(row.dwRemoteAddr), remoteAddrStr, INET_ADDRSTRLEN);

        // Determine the protocol (TCP or UDP)
        std::string protocol = (row.dwState == MIB_TCP_STATE_LISTEN) ? "TCP" : "UDP";

        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
        if (hProcess != nullptr) {
            char processName[MAX_PATH];
            DWORD size = sizeof(processName);
            if (QueryFullProcessImageNameA(hProcess, 0, processName, &size) != 0) {
                std::cout << std::setw(14) << row.dwOwningPid << std::setw(maxProcessNameLength + 2) << processName << std::setw(24) 
                    << localAddrStr << ":" << std::setw(5)
                    << ntohs(static_cast<u_short>(row.dwLocalPort)) << std::setw(24) << remoteAddrStr << ":" << std::setw(5)
                    << ntohs(static_cast<u_short>(row.dwRemotePort)) << std::setw(10) << protocol << std::setw(16) 
                    << GetStateString(row.dwState) << "\n";
            }
            CloseHandle(hProcess);
        }
    }

    std::cout << separatorLine << std::endl;
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock\n";
        return 1;
    }

    // Get TCP table
    MIB_TCPTABLE_OWNER_PID* pTcpTable;
    DWORD dwSize = 0;
    if (GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get TCP table size\n";
        WSACleanup();
        return 1;
    }

    pTcpTable = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(new char[dwSize]);
    if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        std::cerr << "Failed to get TCP table\n";
        delete[] reinterpret_cast<char*>(pTcpTable);
        WSACleanup();
        return 1;
    }

    // Print socket information
    PrintSocketInfo(pTcpTable);

    // Cleanup
    delete[] reinterpret_cast<char*>(pTcpTable);
    WSACleanup();
    system("pause");
    return 0;
}
