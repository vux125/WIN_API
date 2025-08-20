#include<windows.h>
#include<stdio.h>
#include<string>

#include "sendRecvFileSocket.cpp"

#pragma comment(lib, "ws2_32.lib")


using namespace std;

SYSTEMTIME st;
int stt = 1;
HANDLE h_Input_Console = GetStdHandle(STD_INPUT_HANDLE);
HANDLE h_Output_Console = GetStdHandle(STD_OUTPUT_HANDLE);
void print_notion(const string &str) {
	DWORD written;
	WriteConsoleA(h_Output_Console, str.c_str(), str.length(), &written, NULL);
}

void input_notion( char* str, int size) {
	DWORD read;
	ReadConsoleA(h_Input_Console, str, size - 1, &read, nullptr);
	if(read > 2) {
		str[read - 2] = '\0'; 
	} else {
		str[0] = '\0';
	}
}

int main() {

	WSADATA wsaData;

	struct sockaddr_in server, client;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET socket_server = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_server == INVALID_SOCKET) {
		print_notion("Socket creation failed with error\n");
		return 1;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(8080);

	if (bind(socket_server, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
		print_notion("Bind failed with error\n");
		closesocket(socket_server);
		return 1;
	}

	
	while (true) {
		listen(socket_server, 1);
		print_notion("Server is listening on port 8080...\n");
		int clientSize = sizeof(client);
		SOCKET clientSocket = accept(socket_server, (struct sockaddr*)&client, &clientSize);
		if (clientSocket == INVALID_SOCKET) {
			print_notion("Accept failed with error\n");
			closesocket(socket_server);
			return 1;
		}
		print_notion("Client connected.\n");

		char option[2];
		int receive_option = recv(clientSocket, option, sizeof(option) - 1, 0);
		option[receive_option] = '\0';
		if (receive_option == SOCKET_ERROR) {
			print_notion("Receive failed with error\n");
			closesocket(clientSocket);
			continue;
		}
		if (strcmp(option, "1") == 0) {
			while (true) {
				char buffer[1024];

				int recv_client = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
				if (recv_client == SOCKET_ERROR) {
					print_notion("Receive failed with error\n");
					closesocket(clientSocket);
					break;
				}

				buffer[recv_client] = '\0';
				if (recv_client == 0) {
					print_notion("Client disconnected.\n");
					closesocket(clientSocket);
					continue;
				}
				print_notion("Client:");
				print_notion(buffer);
				print_notion("\n");

				char send_data[1024];
				print_notion("Server: ");
				input_notion(send_data, sizeof(send_data));
				if(strcmp(send_data, "exit") == 0) {
					print_notion("Server is shutting down.\n");
					closesocket(clientSocket);
					break;
				}
				int send_client = send(clientSocket, send_data, strlen(send_data), 0);
				if (send_client == SOCKET_ERROR) {
					printf("Send failed with error: %d\n", WSAGetLastError());
					closesocket(clientSocket);
					break;
				}
			}
		}
		else if (strcmp(option, "2") == 0) {
			char filePath[512] = "C:\\Users\\My Desktop\\Documents\\Malware\\code\\winapi\\WinSocket\\uploads";
			GetLocalTime(&st);
			string fullName = string(filePath) + "\\file"  + to_string(stt++)+".txt";
			string result = recvFileFromSocket(clientSocket, fullName);
			print_notion(result + "\n");
		}
		closesocket(clientSocket);
		
	}
	
	closesocket(socket_server);
	WSACleanup();




	return 0;
}
