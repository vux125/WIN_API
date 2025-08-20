#include <windows.h>
#include <iostream>
#include <string>

HANDLE hFile;
using namespace std;

string sendFileToSocket(SOCKET socket,const string pathFile) {
	hFile = CreateFileA(pathFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_FILE_NOT_FOUND) {
			return "File not found";
		}
		else {
			return "Error opening file";
		}
	}

	DWORD fileSize = GetFileSize(hFile, NULL);
	char *buffer = new char[fileSize];
	DWORD bytesRead;

	BOOL readResult = ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
	if (!readResult || bytesRead != fileSize) {
		CloseHandle(hFile);
		delete[] buffer;
		return "Error reading file";
	}
	int bytesSent = send(socket, buffer, bytesRead, 0);
	if (bytesSent == SOCKET_ERROR) {
		CloseHandle(hFile);
		delete[] buffer;
		return "Error sending file";
	}
	CloseHandle(hFile);
	delete[] buffer;
	return "File sent successfully";
}


string recvFileFromSocket(SOCKET socket, const string pathFile) {
	hFile = CreateFileA(pathFile.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return "Error creating file";
	}
	char buffer[4096];
	int bytesReceived;
	while ((bytesReceived = recv(socket, buffer, sizeof(buffer), 0)) > 0) {
		DWORD bytesWritten;
		BOOL writeResult = WriteFile(hFile, buffer, bytesReceived, &bytesWritten, NULL);
		if (!writeResult || bytesWritten != bytesReceived) {
			CloseHandle(hFile);
			return "Error writing to file";
		}
	}
	if (bytesReceived == SOCKET_ERROR) {
		CloseHandle(hFile);
		return "Error receiving file";
	}
	CloseHandle(hFile);
	return "File received successfully";
}
