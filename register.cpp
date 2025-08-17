#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#include <string>
#include <iostream> 

#define HKCR HKEY_CLASSES_ROOT 
#define HKCU HKEY_CURRENT_USER 
#define HKLM HKEY_LOCAL_MACHINE
#define HKUS HKEY_USERS 
#define HKCC HKEY_CURRENT_CONFIG

using namespace std;    

void getSubKey(HKEY hkey);
void print_notion(const string &s);
void input_string(string &s);
void createFileOrOpen(HKEY key, string &subKey);    
void deleteKey(HKEY hkey, string &subKey);
void setValueKey(HKEY hkey, string &subKey, string &valueName, string &data);
void readValueToKey(HKEY hkey, string &subKey, string &valueName);
void getInfoKey(HKEY hkey, string &subKey);
void actionKey(HKEY hkey);

int main(){
    while (true)
    {
        print_notion("Chon mot key goc:");
        print_notion("1. HKEY_CLASSES_ROOT");  
        print_notion("2. HKEY_CURRENT_USER");
        print_notion("3. HKEY_LOCAL_MACHINE");
        print_notion("4. HKEY_USERS");
        print_notion("5. HKEY_CURRENT_CONFIG");
        print_notion("6. Thoat");
        print_notion("Nhap lua chon cua ban: ");
        string choice;
        input_string(choice);   
        HKEY hkey;
        if (choice == "1") {
            hkey = HKCR;
        }else if(choice == "2") {
            hkey = HKCU;
        }else if(choice == "3") {
            hkey = HKLM;
        }else if(choice == "4") {
            hkey = HKUS;
        }else if(choice == "5") {
            hkey = HKCC;
        }else if(choice == "6") {
            print_notion("Thoat chuong trinh.");
            break;
        }else {
            print_notion("Lua chon khong hop le. Vui long chon lai.");
            continue;
        }
        system("cls");
        actionKey(hkey);
    } 
    return 0;
}

void print_notion(const string &s){
    HANDLE h_Console = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    string output = s + "\n";
    WriteConsole(h_Console, output.c_str(), (DWORD)output.length(), &written, nullptr);
    return;
}

void input_string(string &s){
    HANDLE h_Console = GetStdHandle(STD_INPUT_HANDLE);
    DWORD read;
    char buffer[100];
    ReadConsoleA(h_Console, buffer,101, &read,nullptr );
    if (read >= 2 && buffer[read-2] =='\r'){
        buffer[read-2] = '\0';
    }else{
        buffer[read] = '\0';
    }
    s = buffer;
    return;
}

void getSubKey(HKEY hkey){
    char subKeyName[256];
    DWORD size = sizeof(subKeyName);
    for(DWORD i = 0; RegEnumKeyExA(hkey, i, subKeyName, &size,NULL,NULL,NULL,NULL) == ERROR_SUCCESS; i++){
        print_notion("Subkey: " + string(subKeyName));
        size = sizeof(subKeyName); 
    }
    RegCloseKey(hkey);
}

void createFileOrOpen(HKEY key, string &subKey){
    HKEY phkResult ;
    DWORD lpdwDisposotion;
    LONG result = RegCreateKeyExA(
        key, //khoa goc
        subKey.c_str(), //subkey
        0, 
        NULL, 
        REG_OPTION_VOLATILE, //chi ton tai trong bo nho mat khi khoi dong lai may
        KEY_ALL_ACCESS, //quyen truy cap mong muon
        NULL,
        &phkResult, //handle lam viec voi key 
        &lpdwDisposotion // status new or open
    );

    if(result == ERROR_SUCCESS){
        if (lpdwDisposotion == REG_CREATED_NEW_KEY){
            print_notion("Key moi da duoc tao");
        }else{
            print_notion("Key da ton tai va duoc mo");
        }
    }else{
        print_notion("Tao key that bai");
    }
    RegCloseKey(phkResult);
}

void deleteKey(HKEY hkey, string &subKey){
    LONG result = RegDeleteKeyExA(
        hkey,
        subKey.c_str(),
        KEY_WOW64_32KEY,
        0
    );
    if(result == ERROR_SUCCESS){
        print_notion("Xoa file thanh cong");
    }else{
        print_notion("Xoa file that bai");
    }
}

void setValueKey(HKEY hkey, string &subKey,string &valueName, string &data){
    HKEY hk;
    LONG res = RegOpenKeyExA(hkey, subKey.c_str(), 0, KEY_ALL_ACCESS, &hk);
    if (res == ERROR_SUCCESS){
        const char * text = data.c_str();
        LONG result = RegSetValueExA(
            hk, 
            valueName.c_str(), 
            0, 
            REG_SZ, 
            (BYTE*) text,
            strlen(text)
        );
        if (result==ERROR_SUCCESS){
            print_notion("Thiet lap gia tri thanh cong");
        }else{
            print_notion("Thiet lap that bai");
        }
    }else{
        print_notion("Key khong ton tai");
    }
    RegCloseKey(hk);
}

void readValueToKey(HKEY hkey, string &subKey, string &valueName){
    HKEY hk;
    LONG res = RegOpenKeyExA(hkey, subKey.c_str(),0,KEY_READ,&hk);
    if (res == ERROR_SUCCESS){
        char buffer[256];
        DWORD type;
        DWORD size = sizeof(buffer);
        LONG result = RegQueryValueExA(
            hk,
            valueName.c_str(),
            0,
            &type,
            (BYTE*)buffer,
            &size
        );
        if (result==ERROR_SUCCESS){
            string s = buffer;
            print_notion("Value: "+s);
        }else{
            print_notion("Khong lay duoc gia tri");
        }
    }else{
        print_notion("Key khong ton tai");
    }
    RegCloseKey(hk);
}

void getInfoKey(HKEY hkey, string &subKey){
    HKEY hk;
    if(RegOpenKeyExA(hkey, subKey.c_str(),0, KEY_READ, &hk) == ERROR_SUCCESS){
        DWORD   lpcSubKeys = 0;               // [out] Số lượng subkey
        DWORD   lpcchMaxSubKeyLen = 0;        // [out] Độ dài tên subkey dài nhất (không tính '\0')
        DWORD   lpcchMaxClassLen = 0;         // [out] Độ dài class string dài nhất trong các subkey
        DWORD   lpcValues = 0;                // [out] Số lượng value trong key
        DWORD   lpcchMaxValueNameLen = 0;     // [out] Độ dài tên value dài nhất (không tính '\0')
        DWORD   lpcbMaxValueLen = 0;          // [out] Kích thước dữ liệu value lớn nhất (bytes)
        DWORD   lpcbSecurityDescriptor = 0;   // [out] Kích thước security descriptor của key (bytes)
        FILETIME ftLastWriteTime = {0};       // [out] Thời gian cuối cùng key được ghi (UTC)
        LONG result = RegQueryInfoKeyA(hk, NULL, NULL, NULL,
            &lpcSubKeys,
            &lpcchMaxSubKeyLen,
            &lpcchMaxClassLen,
            &lpcValues,
            &lpcchMaxValueNameLen,
            &lpcbMaxValueLen,
            &lpcbSecurityDescriptor,
            &ftLastWriteTime
        );
        if (result == ERROR_SUCCESS){
            print_notion("Thong tin key:");
            print_notion("Subkey: " + subKey);
            print_notion("Number of subkeys: " + to_string(lpcSubKeys));
            print_notion("Max subkey length: " + to_string(lpcchMaxSubKeyLen));
            print_notion("Max class length: " + to_string(lpcchMaxClassLen));
            print_notion("Number of values: " + to_string(lpcValues)); 
            print_notion("Max value name length: " + to_string(lpcchMaxValueNameLen));
            print_notion("Max value length: " + to_string(lpcbMaxValueLen));
            print_notion("Security descriptor size: " + to_string(lpcbSecurityDescriptor));
            SYSTEMTIME st;
            FileTimeToSystemTime(&ftLastWriteTime, &st);
            print_notion("Last write time: " + to_string(st.wYear) + "-" + to_string(st.wMonth) + "-" +
                         to_string(st.wDay) + " " + to_string(st.wHour) + ":" + to_string(st.wMinute) + ":" +
                         to_string(st.wSecond));       
        }else{
            print_notion("Doc thong tin key that bai");
        }
    }else{
        print_notion("Key khong ton tai");
    }
}

void actionKey(HKEY hkey){
    while (true) {
        print_notion("Chon mot hanh dong:");
        print_notion("1. Lay danh sach subkey");
        print_notion("2. Tao hoac mo mot file");
        print_notion("3. Xoa mot key");
        print_notion("4. Thiet lap gia tri cho mot key");
        print_notion("5. Doc gia tri cua mot key");
        print_notion("6. Lay thong tin ve mot key");
        print_notion("7. Tro ve menu chinh");
        print_notion("Nhap lua chon cua ban: ");
        
        string choice;
        input_string(choice);
        
        if (choice == "1") {
            getSubKey(hkey);
        } else if (choice == "2") {
            string subKey;
            print_notion("Nhap ten subkey: ");
            input_string(subKey);
            createFileOrOpen(hkey, subKey);
        } else if (choice == "3") {
            string subKey;
            print_notion("Nhap ten subkey can xoa: ");
            input_string(subKey);
            deleteKey(hkey, subKey);
        } else if (choice == "4") {
            string subKey, valueName, data;
            print_notion("Nhap ten subkey: ");
            input_string(subKey);
            print_notion("Nhap ten value: ");
            input_string(valueName);
            print_notion("Nhap du lieu cho value: ");
            input_string(data);
            setValueKey(hkey, subKey, valueName, data);
        } else if (choice == "5") {
            string subKey, valueName;
            print_notion("Nhap ten subkey: ");
            input_string(subKey);
            print_notion("Nhap ten value: ");
            input_string(valueName);
            readValueToKey(hkey, subKey, valueName);
        } else if (choice == "6") {
            string subKey;
            print_notion("Nhap ten subkey: ");
            input_string(subKey);
            getInfoKey(hkey, subKey);
        } else if (choice == "7") {
            break;
        } else {
            print_notion("Lua chon khong hop le. Vui long chon lai.");
        }
    }
}