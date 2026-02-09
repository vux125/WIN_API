.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

.data

	input db "input.txt",0
	hInput dd 0
	output db "output.txt", 0
	hOutput dd 0
	
	path db 512 dup(0)
	tmp db 512 dup(0)
	
	ext db 10 dup(0)
	
	wfd WIN32_FIND_DATAA <>
	
	
	ente db 13, 10
	fullPath db 512 dup(0)
	excep db ".",0,"..", 0
	sizePath dw 0
	
	cn db "\", "*", 0
.code

DuyetFile PROC uses eax ebx ecx edx, pathFile:dword
	
	LOCAL hfind:dword
	LOCAL pathtmp[512]:byte
	 
	
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
	jnz		checkhome
	
	push	offset ext
	call	lstrlen
	push	eax
	
	push	offset wfd.cFileName
	call	lstrlen
	xor		ecx, ecx
	pop		ecx
	
	sub		eax, ecx
	
	xor		edx, edx
	mov		edx, offset wfd.cFileName
	
	add		edx, eax
	
	push	offset ext
	push	edx
	call	lstrcmp
	
	jne		filetieptheo
	jmp		tiep
	checkhome:
	push	offset wfd.cFileName
	push	offset excep
	call	lstrcmp
	cmp		eax, 0
	je		filetieptheo
	
	xor		eax, eax
	mov		eax, offset excep
	add		eax, 2
	
	push	eax
	push	offset wfd.cFileName
	call	lstrcmp
	
	cmp		eax, 0
	je		filetieptheo
	
	
	
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
	jmp		filetieptheo
	
	tiep:
	
	push	pathFile
	call	lstrlen
	dec		eax
	
	push	NULL
	push	NULL
	push 	eax
	push	pathFile 
	push	hOutput
	call	WriteFile
	
	
	push	offset wfd.cFileName
	call	lstrlen
	
	push	NULL
	push	NULL
	push 	eax
	push	offset wfd.cFileName 
	push	hOutput
	call	WriteFile
	
	push	NULL
	push	NULL
	push 	2
	push	offset ente
	push	hOutput
	call	WriteFile
	
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
	
	push	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	CREATE_ALWAYS
	push	NULL
	push	FILE_SHARE_READ or FILE_SHARE_WRITE
	push	GENERIC_READ or GENERIC_WRITE
	push	offset output
	call	CreateFile
	
	mov		hOutput, eax
	
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
	
	push	0
	push	0
	push 	eax	
	push	hInput
	call	SetFilePointer
	
	push	NULL
	push	NULL
	push	10
	push	offset ext
	push	hInput
	call	ReadFile
	
	pop		ecx
	push	offset cn
	push	ecx
	call	lstrcpy
	
	push	offset path
	call	DuyetFile
	
	ret
	
	
end start
