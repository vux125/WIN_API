
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h> 
#include <stdio.h>
#include <string>

#include "sendRecvFileSocket.cpp"

#pragma comment(lib, "ws2_32.lib")

using namespace std;
HANDLE h_Input_Console = GetStdHandle(STD_INPUT_HANDLE);
HANDLE h_Out_Console = GetStdHandle(STD_OUTPUT_HANDLE);

void print_notion(const string& str) {
    DWORD dwWritten;
    WriteConsoleA(h_Out_Console, str.c_str(), str.length(), &dwWritten, NULL);
}   

void input_notion(char* str, int size) {
    DWORD dwRead;
    ReadConsoleA(h_Input_Console, str, size, &dwRead, NULL);
    if (dwRead > 2) {
        str[dwRead - 2] = '\0';
    }
    else {
        str[dwRead] = '\0';
    }
}


using namespace std;

int main() {
    WSADATA wsaData;
    struct sockaddr_in server;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        print_notion("WSAStartup failed with error");
        return 1;
    }

    SOCKET socket_client = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_client == INVALID_SOCKET) {
        print_notion("Socket creation failed with error");
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    string str = "127.0.0.1";


    int wchars_num = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    WCHAR* wstr = new WCHAR[wchars_num];
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wstr, wchars_num);
    if (InetPton(AF_INET, wstr, &server.sin_addr) != 1) {
        print_notion("Invalid IP address format.\n");
        closesocket(socket_client);
        WSACleanup();
        return 1;
    }

    if (connect(socket_client, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        print_notion("Connection failed with error");
        closesocket(socket_client);
        WSACleanup();
        return 1;
    }
    while (true) {
        char num[10];
        print_notion("Enter option:\n1: Send message\n2:Upload file\n3:Disconnec\n");
        input_notion(num, sizeof(num));

        print_notion("You entered: ");
        print_notion(num);
        print_notion("\n");

        if (strcmp(num, "2") == 0) {
            int send_option = send(socket_client, num, strlen(num), 0);
            print_notion("Enter file path to upload: ");
            char file_path[1024];
            input_notion(file_path, sizeof(file_path) - 1);
            string result = sendFileToSocket(socket_client, file_path);
            print_notion(result + "\n");
			continue; 
        }else if(strcmp(num, "3") == 0) {
			print_notion("Disconnecting....\n");    
			break;
		}

        while (true) {
            int send_option = send(socket_client, num, strlen(num), 0);
            char send_data[1024];
            print_notion("Client: ");
            input_notion(send_data, sizeof(send_data) - 1);
            if (strcmp(send_data, "exit") == 0) {
                print_notion("Exiting client...\n");
                break;
            }
            int send_server = send(socket_client, send_data, strlen(send_data), 0);
            if (send_server == SOCKET_ERROR) {
                print_notion("Send failed with error");
                closesocket(socket_client);
                WSACleanup();
                return 1;
            }

            char buffer[1024];
            int recv_size = recv(socket_client, buffer, sizeof(buffer) - 1, 0);
            if (recv_size == SOCKET_ERROR) {
                print_notion("Receive failed with error");
                closesocket(socket_client);
                WSACleanup();
                return 1;
            }
            buffer[recv_size] = '\0';
            print_notion("Server: ");
            print_notion(buffer);
            print_notion("\n");
        }
        
    }
    closesocket(socket_client);
    WSACleanup();
    return 0;
}
