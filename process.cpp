#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#pragma comment(lib, "advapi32.lib")
using namespace std;

HANDLE h_Console_Output = GetStdHandle(STD_OUTPUT_HANDLE);
HANDLE h_Console_Input = GetStdHandle(STD_INPUT_HANDLE);


void print_notion(const string &s); 
void input_string(string &s); 
void createProcess();
void enumProcess();
void killProcess();


int main() {
    while (true) {
        print_notion("Chon mot hanh dong:");
        print_notion("1. Tao tien trinh moi");
        print_notion("2. Liet ke cac tien trinh hien tai");
        print_notion("3. Ket thuc mot tien trinh");
        print_notion("4. Thoat");
        print_notion("Nhap lua chon cua ban: ");
        
        string choice;
        input_string(choice);
        
        if (choice == "1") {
            createProcess();
        } else if (choice == "2") {
            enumProcess();
        } else if (choice == "3") {
            killProcess();
        } else if (choice == "4") {
            print_notion("Thoat chuong trinh.");
            break;
        } else {
            print_notion("Lua chon khong hop le. Vui long chon lai.");
        }
    }
    
    return 0;
}

void print_notion(const string &s) { 
    DWORD written;
    string res = s+"\n";
    WriteConsole(h_Console_Output, res.c_str(), (DWORD)res.length(), &written, nullptr);
}

void input_string(string &s){  
    char fbuffer[256] = {0};
    DWORD read;
    ReadConsoleA(h_Console_Input, fbuffer, sizeof(fbuffer)-1, &read, nullptr);
    if (read >= 2 && fbuffer[read-2] =='\r'){
        fbuffer[read-2] = '\0';
    }else{
        fbuffer[read] = '\0';
    }
    s = fbuffer;
    return;
}

void createProcess(){
    print_notion("Dang nhap de tao tien trinh moi:");
    HANDLE hToken;
    string username, domain, password;
    print_notion("Nhap ten nguoi dung:");
    input_string(username);
    print_notion("Nhap ten mien:");     
    input_string(domain);
    print_notion("Nhap mat khau:");
    input_string(password);
    if(!LogonUserA(
        username.c_str(),
        domain.c_str(),
        password.c_str(),
        LOGON32_LOGON_INTERACTIVE, 
        LOGON32_PROVIDER_DEFAULT, 
        &hToken)){
        print_notion("Dang nhap that bai");
        return;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    print_notion("Nhap ten tien trinh muon tao:");
    string processName;
    input_string(processName);
    if(!CreateProcessAsUserA(
        hToken,
        processName.c_str(),
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi)){
        print_notion("Tao tien trinh that bai");
    }else{
        print_notion("Tien trinh da duoc tao thanh cong");
        print_notion("PID: " + to_string(pi.dwProcessId));
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
        CloseHandle(hToken);
        return;
}

void enumProcess(){
    HANDLE hSnapshor = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 lppe;
    DWORD stt = 1;
    if(Process32First(hSnapshor, &lppe)){
        do
        {   
            wstring wname = lppe.szExeFile;
            string name(wname.begin(), wname.end());
            print_notion("Process " + to_string(stt) + ": " + name + " (PID: " + to_string(lppe.th32ProcessID) + ")" + " Threads: " + to_string(lppe.cntThreads)  + " Parent PID: " + to_string(lppe.th32ParentProcessID));
            stt++;
            
        } while (Process32Next(hSnapshor, &lppe));
    }else{
        print_notion("Khong the lay thong tin tien trinh");
    }
    CloseHandle(hSnapshor);
    print_notion("Tong so tien trinh: " + to_string(stt - 1));
}

void killProcess(){
    print_notion("Nhap PID cua tien trinh muon ket thuc:");
    string pidStr;
    input_string(pidStr);
    DWORD pid = stoi(pidStr);
    
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        print_notion("Khong the mo tien trinh voi PID: " + pidStr);
        return;
    }
    
    if (TerminateProcess(hProcess, 0)) {
        print_notion("Tien trinh voi PID: " + pidStr + " da duoc ket thuc.");
    } else {
        print_notion("Khong the ket thuc tien trinh voi PID: " + pidStr);
    }
    CloseHandle(hProcess);
}