## Bài 1. Sử dụng WinAPI để đọc, ghi , sửa, xóa và in ra màn hình console

- Sử dụng các hàm: WriteConsole, ReadConsole, CreateFileA, GetFileSize, ReadFile, SetFilePointer,  DeleteFileA, ...

- [Xem code tại đây](https://github.com/vux125/WIN_API/blob/main/console_and_file.cpp)

## Bài 2. Sử dụng WinAPI để đọc Registry, thêm, sửa, xóa registry

- Sử dụng các hàm:  RegEnumKeyExA, RegCreateKeyExA, RegDeleteKeyExA, RegOpenKeyExA, RegQueryInfoKeyA, ...

- [Xem code tại đây](https://github.com/vux125/WIN_API/blob/main/register.cpp)

## Bài 3. Sư dụng WinAPI để tạo, đọc và xóa tiến trìn

- Sử dụng các hàm: CreateProcessAsUserA, CreateToolhelp32Snapshot, OpenProcess, TerminateProcess, ...

- [Xem code tại đây](https://github.com/vux125/WIN_API/blob/main/process.cpp)

## Bài 4. Sử dụng WinAPI để tạo socket truyền tải file

- Sử dụng các hàm: WSAStartup, socket, connect, send, recv, bind, listen, accept, ...

- [Xem code tại đây](https://github.com/vux125/WIN_API/tree/main/Socket)

## Bài 5. Sử dụng assembly để lập trình tính tổng các số nguyên tố trong mảng

- Các thanh ghi: eax, ebx, ecx, edx, ebp, esi, edi, esp và các cờ.

- Các câu lệnh cơ bản: mov, add, sub, mul, div, je, jne, cmp, jb, jnb, ja, jna, rol, ...

- Gọi API trong assembly.

- [Xem code tại đây](https://github.com/vux125/WIN_API/blob/main/tongsonguyento.Asm)

## Bài 6. Sử dụng assembly để đọc thông tin PE file

- Dùng các hàm API: ReadFile, CreateFile, WriteFile, SetFilePointer, ...

- Thực hiện đọc thông tin các phần: DOS Header, PE Header, Section Table, IAT, ... ghi vào file output.txt

- [Xem code chi tiết](https://github.com/vux125/WIN_API/blob/main/PE/PEFile.Asm)
