.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib


GetFinalPathNameByHandleA PROTO :DWORD,:DWORD,:DWORD,:DWORD
WFD STRUCT    
	dwFileAttributes      DWORD   0    
	ftCreationTime        DWORD   2 DUP(0)    
	ftLastAccessTime      DWORD   2 DUP(0)    
	ftLastWriteTime       DWORD   2 DUP(0)    
	nFileSizeHigh         DWORD   0    
	nFileSizeLow          DWORD   0    
	dwReserved0           DWORD   0    
	dwReserved1           DWORD   0    
	cFileName             BYTE    260 DUP(0)    
	cAlternateFileName    BYTE    14 DUP(0)
WFD ENDS

.data

	input 			db "input.txt",0
	hInput 			dd 0
	path 			db 512 dup(0)
	tmp 			db 512 dup(0)
	ext 			db 10 dup(0)
	wfd 			WFD <>
	ente 			db 13, 10
	fullPath 		db 512 dup(0)
	excep 			db ".",0,"..", 0
	sizePath 		dw 0
	cn 				db "\", "*", 0
	ov				dd 5 dup(0)
	hFile			dd 0
.code

CleanFile PROC uses eax ebx ecx edx, handle:dword, file:dword
	
	LOCAL lfanew:dword
	LOCAL numbersection:word
	LOCAL sectionAlign:dword
	LOCAL fileAlign:dword
	LOCAL sizeImage:dword
	LOCAL tls_rva:dword
	LOCAL tls_size:dword
	LOCAL section[10]:dword
	LOCAL tm[MAX_PATH]:byte
	
	lea		ebx, ov
	add		ebx, 8
	xor		eax, eax
	mov		eax, 3ch
	mov		[ebx], eax
	lea		ecx, lfanew
	
	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	ReadFile			;doc e_lfanew
	
	mov		eax, lfanew
	add		eax, 6
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, numbersection

	push	offset ov
	push	0
	push	2
	push	ecx
	push	handle
	call	ReadFile			;doc numberofsection
	
	mov		eax, lfanew
	add		eax, 38h
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, sectionAlign

	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	ReadFile			;doc sectionAlignment
	
	mov		eax, lfanew
	add		eax, 3ch
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, fileAlign

	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	ReadFile			;doc fileAlignment
	
	mov		eax, lfanew
	add		eax, 50h
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, sizeImage

	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	ReadFile			;doc SizeOfImage
	
	mov		eax, lfanew
	add		eax, 0c0h
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, tls_rva

	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	ReadFile			;doc TLS Directory RVA
	
	mov		eax, lfanew
	add		eax, 0c4h
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, tls_size

	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	ReadFile			;doc TLS Directory size
	
	mov		ax, numbersection
	sub		eax, 2
	xor		ebx, ebx
	mov		ebx, 28h
	mul 	ebx
	mov		ebx, eax
	
	mov		eax, lfanew
	add		eax, 0f8h
	add		eax, ebx
	
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, section

	push	offset ov
	push	0
	push	14h
	push	ecx
	push	handle
	call	ReadFile			;doc thong tin section ap chot trong bang section
	
	mov		eax, tls_rva
	mov		ebx, tls_size
	cmp		ebx, 0ffffffffh
	jne		no_virus
	
	;---------------dong va xoa file neu no la virus goc
	push	handle
	call	CloseHandle
	
	push	file
	call	DeleteFile
	jmp 	done
	
	no_virus:
	cmp		eax, 00000000h
	je		check_size
	jmp		done
	
	check_size:
	cmp		ebx, 00000000h
	je		done
	
	mov		ax, numbersection
	sub		ax, 1
	mov		numbersection, ax	;giam section di 1
	
	lea		edx, section
	add		edx, 8
	mov		eax, [edx]
	add		edx, 4
	mov		ebx, [edx]
	add		eax, ebx			
	
	mov		ebx, sectionAlign
	
	;sua lai image size
	loop_image_size:
	cmp		eax, ebx
	ja		inc_image
	mov		sizeImage, ebx
	jmp		done_loop_image_size
	
	inc_image:
	add		ebx, sectionAlign
	jmp		loop_image_size
	
	;sua file bi lay virus
	done_loop_image_size:
	
	mov		eax, lfanew
	add		eax, 6
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, numbersection
	
	push	offset ov
	push	0
	push	2
	push	ecx
	push	handle
	call	WriteFile			;modify NumberOfSection
	
	
	mov		eax, lfanew
	add		eax, 28h
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, tls_size
	
	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	WriteFile			;modify AddressOfEntrypoint
	
	mov		eax, lfanew
	add		eax, 50h
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, sizeImage

	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	WriteFile			;modify SizeOfImage
	
	mov		eax, lfanew
	add		eax, 0c4h
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, tls_rva

	push	offset ov
	push	0
	push	4
	push	ecx
	push	handle
	call	WriteFile			;modify TLS Directory size
	
	lea		ebx, section
	
	push	28h
	push	ebx	
	call	RtlZeroMemory
	
	xor		eax, eax
	mov		ax, numbersection
	xor		ebx, ebx
	mov		ebx, 28h
	mul 	ebx
	mov		ebx, eax
	
	mov		eax, lfanew
	add		eax, 0f8h
	add		eax, ebx
	
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, section

	push	offset ov
	push	0
	push	28h
	push	ecx
	push	handle
	call	ReadFile			;doc thong tin section virus trong bang section
	
	lea		edx, section
	add		edx, 10h
	mov		ebx, [edx]
	
	push	PAGE_READWRITE
	push	3000h
	push	ebx
	push	NULL
	call 	VirtualAlloc
	
	lea		edx, section
	mov		[edx], eax			;luu dia chi bo nho duoc cap phat
	add		edx, 10h
	mov		ebx, [edx]
	
	push	ebx
	push	eax	
	call	RtlZeroMemory
	
	lea		edx, section
	add		edx, 14h
	mov		ebx, [edx]
	
	lea		edx, section
	add		edx, 10h
	mov		edx, [edx]
	
	lea		eax, ov
	add		eax, 8
	mov		[eax], ebx
	lea		ecx, section
	mov		ecx, [ecx]
	
	push	offset ov
	push	0
	push	edx
	push	ecx
	push	handle
	call	WriteFile			;modify section virus
	
	lea		edx, section
	
	push	28h
	push	edx
	call	RtlZeroMemory
	
	xor 	eax, eax
	mov		ax, numbersection
	xor		ebx, ebx
	mov		ebx, 28h
	mul 	ebx
	mov		ebx, eax
	
	mov		eax, lfanew
	add		eax, 0f8h
	add		eax, ebx
	
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ecx, section

	push	offset ov
	push	0
	push	28h
	push	ecx
	push	handle
	call	WriteFile				;zeromemory section virus
	
	push	handle
	call	CloseHandle	
	done:
	
	ret

CleanFile endp



DuyetFile PROC uses eax ebx ecx edx, pathFile:dword
	
	LOCAL hfind:dword
	LOCAL pathtmp[512]:byte
	LOCAL hfile:dword
	LOCAL mz:word 
	
	push 	offset wfd
	push	pathFile
	call	FindFirstFile
	
	mov		hfind, eax
	cmp		eax, INVALID_HANDLE_VALUE
	jne		lap
	ret
	
	lap:
	
	xor 	eax, eax
	mov		eax, wfd.dwFileAttributes
	test	eax, FILE_ATTRIBUTE_DIRECTORY
	jnz		checkhome						;neu la thu muc thi nhay check . ..
	;------------------------------------
	push	pathFile
	push	offset tmp
	call	lstrcpy
	
	
	
	push	offset tmp
	call	lstrlen
	
	mov		ebx, offset tmp
	add		ebx, eax
	dec		ebx
	
	push	offset wfd.cFileName
	push	ebx
	call	lstrcpy
	
	
	push	0
	push	80h					;normal
	push	3					;OPEN_EXISTING
	push	0
	push 	3
	push 	0C0000000h
	push	offset tmp			;tmp
	call	CreateFile			;CreateFile
	
	lea		ebx, hfile
	mov		[ebx], eax
	mov		ebx, [ebx]
	lea		eax, mz
	
	push	NULL
	push	0
	push	2
	push	eax
	push	ebx
	call	ReadFile
	
	mov		ax, mz
	mov		bx, 5a4dh
	cmp		ax, bx
	jne		filetieptheo
	
	push	offset tmp
	push	hfile
	call	CleanFile
	
	push	200h
	push	offset tmp
	call	RtlZeroMemory
	
	jmp		filetieptheo
	;------------------------------------
	checkhome:
	push	offset wfd.cFileName
	push	offset excep
	call	lstrcmp
	cmp		eax, 0		;check .
	je		filetieptheo
	
	xor		eax, eax
	mov		eax, offset excep
	add		eax, 2		;check ..
	
	push	eax
	push	offset wfd.cFileName
	call	lstrcmp
	
	cmp		eax, 0
	je		filetieptheo
	
	; neu dung thi nhay toi findnextfile
	;neu khong thi check junction
	checkjunction:
		test	eax, FILE_ATTRIBUTE_REPARSE_POINT
		jnz		filetieptheo
		
	xor		eax, eax
	lea		eax, pathtmp
	push	pathFile
	push	eax
	call	lstrcpy
	
	lea		eax, pathtmp
	push	eax	
	call	lstrlen
	
	xor 	ecx, ecx
	lea		ecx, pathtmp
	add		ecx, eax
	sub		ecx, 1
	

	push	offset wfd.cFileName
	push	ecx
	call	lstrcpy
	
	xor		eax, eax
	lea		eax, pathtmp
	push	eax	
	call	lstrlen
	
	lea		ecx,  pathtmp
	add		ecx, eax
	
	push 	offset cn
	push	ecx 
	call	lstrcpy
	
	xor		eax, eax
	lea		eax, pathtmp
	
	push	eax	
	call 	DuyetFile
	
	filetieptheo:
	
		
	push	offset wfd
	push 	hfind
	call	FindNextFile
	
	cmp		eax, 0
	je		done
	jmp 	lap
	
	done:
	push	hfind
	call	FindClose
	ret

DuyetFile endp

start:

	push	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ
	push	GENERIC_READ
	push	offset input
	call	CreateFile
	
	mov		hInput, eax
	
	
	
	xor		ecx, ecx
	mov		ecx, offset path
	
	
	readPath:
	push	ecx
	
	push	NULL
	push	NULL
	push	1
	push	ecx
	push	hInput
	call	ReadFile
	
	pop 	ecx
	xor 	eax, eax
	mov		al, [ecx]
	inc		ecx
	cmp		al, 0Dh
	jne		readPath
	
	dec		ecx
	push	ecx
	
	push	offset path
	call	lstrlen
	
	add		eax, 1
	
	pop		ecx
	push	offset cn
	push	ecx
	call	lstrcpy
	
	push	offset path
	call	DuyetFile
	
	ret
	
	
end start
