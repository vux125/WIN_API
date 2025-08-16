#include <windows.h>
#include <string>
#include <iostream>
using namespace std;

void print_notion(const string &s);
void input_string(string &s);
void readFile(const string &fileName, string &buffer);
void inputFile();
void deleteFile();


void main(){
    while(true){
        print_notion("Ban muon lam gi:");
        print_notion("0. Thoat");
        print_notion("1. In chuoi ra man hinh");
        print_notion("2. Doc file va in ra console");
        print_notion("3. Ghi du lieu vao file");
        print_notion("4. Xoa file");
        print_notion("Chon so thu tu cua chuc nang ban muon: ");
        string num;
        input_string(num);
        int cn;
        try
        {
            cn = stoi(num);
            if(cn>4 && cn <0){
                continue;
            }
        }
        catch(const std::exception& e)
        {
            print_notion("Invalid");
            continue;
        }

        switch (cn)
        {
            case 0:
            {
                print_notion("Thoat chuong trinh");
                return;
            }
            case 1:
            {   
                string display;
                print_notion("Nhap chuoi muon in ra");
                input_string(display);
                print_notion(display);
                break;
            }
            case 2:
            {
                string nameFile;
                print_notion("Nhap ten file:");
                input_string(nameFile);
                string text;
                readFile(nameFile, text);
                print_notion(text);
                break;
            }
            case 3:
            {
                inputFile();
                break;
            }
            case 4:
            {
                deleteFile();
                break;
            }  
        }
    }
}

void print_notion(const string &s){ //in du lieu ra console
    HANDLE h_Console_Output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD read;
    string wr = s + "\n";
    WriteConsole(h_Console_Output, wr.c_str(), (DWORD) wr.length(), &read, nullptr);
    
    return;
}
void input_string(string &s){   // nhap du lieu vao tu console

    HANDLE h_Console_Input = GetStdHandle(STD_INPUT_HANDLE);
    char fbuffer[101] = {0};
    DWORD nNumberOfCharToRead = 100;
    DWORD read;
    ReadConsole(h_Console_Input, fbuffer, nNumberOfCharToRead, &read, nullptr);
    if (read >= 2 && fbuffer[read-2] =='\r'){
        fbuffer[read-2] = '\0';
    }else{
        fbuffer[read] = '\0';
    }
    s = fbuffer;
    return;
}

void readFile(const string &fileName, string &buffer){   // doc file va ghi noi dung vao buffer
    HANDLE h_File = CreateFileA(fileName.c_str(),GENERIC_ALL, FILE_SHARE_READ|FILE_SHARE_WRITE,NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,NULL);
    if(h_File == INVALID_HANDLE_VALUE){
        if(GetLastError()== ERROR_FILE_NOT_FOUND){
            print_notion("File not found\n");
        }else{
            print_notion("Cannot file\n");
        }
        return;
    }
    DWORD filesize = GetFileSize(h_File,NULL);
    if (filesize == INVALID_FILE_SIZE){
        print_notion("Unable to get file size");
        CloseHandle(h_File);
    }
    DWORD read;
    buffer.resize(filesize);
    BOOL result = ReadFile(h_File, &buffer[0], filesize, &read, NULL);
    CloseHandle(h_File);
    if(!result){
        print_notion("Read failure");
    }
    buffer.resize(read);
}

void inputFile(){   // tao moi va ghi neu file chua ton tai - ghi vao cuoi file neu file da ton tai
    print_notion("Nhap duong dan toi file ban muon mo: ");
    string nameFile;
    input_string(nameFile);
    HANDLE h_File = CreateFileA(nameFile.c_str(),GENERIC_ALL,FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL ,NULL);
    if(h_File == INVALID_HANDLE_VALUE){
        print_notion("File name invalid");
        return;
    }
    SetFilePointer(h_File, 0, NULL, FILE_END);
    string res[100];
    print_notion("Nhap so luong dong muon ghi vao file:");
    string num_s;
    input_string(num_s);
    int num_i = stoi(num_s);
    for (int i = 0; i < num_i ; i++){
        input_string(res[i]);
    }
    string wr;
    for (int i=0; i<3;i++){
       wr += res[i];
       wr += "\n";
    }
    DWORD write;
    WriteFile(h_File, wr.c_str(), (DWORD)wr.length(), &write, NULL);
    CloseHandle(h_File);
}

void deleteFile(){
    string pathFile;
    print_notion("Nhap ten file muon xoa");

    input_string(pathFile);
    BOOL status = DeleteFileA((LPCSTR)pathFile.c_str());
    if(status == FALSE){
        print_notion("Xoa file khong thanh cong");

    }else{
        print_notion("Xoa file thanh cong");
    }
    
}