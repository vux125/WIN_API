.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib


.data

	file 				db "ActiveSyncProvider.dll", 0
	hFile 				dd 0
	
	output 				db "output.txt", 0
	hOutput 			dd 0
	ente				db 13, 10, 0
	
	tmp 				db	16 dup(0)
	
	chuoi 				db "0123456789ABCDEF", 0
	
	data				db	128 dup(0)
			
	
	;ten bien trong pe
	;DOS Header
	titDos					db "----------------DOS HEADER--------------", 0
	e_magic 				db "e_magic", 0
	e_lfanew				db "e_lfanew", 0
	;PE Header
	titPEHeader				db "----------------PE HEADER---------------", 0
	signature 				db "Signature", 0
	;PE Header-File Header
	titPEHeaderFileHeader	db "--------PE HEADER - FILE HEADER---------", 0
	machine					db "Machine", 0
	numberofsections 		db "NumberOfSections", 0
	sizeofoptionalheader 	db "SizeOfOptionalHeader", 0
	characreristics			db "Characreristics", 0
	;PE Header-Optional Header
	titPEHeaderOptional		db "------PE HEADER - OPTIONAL HEADER-------", 0
	magic 					db "Magic", 0
	sizeofcode				db "SizeOfCode", 0
	sizeofinitializeddata	db "SizeOfInitializedData", 0
	sizeofUnitializeddata	db "SizeOfUnitializedData", 0
	addressofentrypoint		db "AddressOfEntryPoint", 0
	baseofcode				db "", 0
	baseofdata				db "", 0
	imagebase				db "", 0
	sectionalignment		db "", 0
	filealignment			db "", 0
	sizeofimage				db "", 0
	sizeofheader			db "", 0
	datadirectory			db "", 0
	export					db "", 0
	import					db "", 0
	resource				db "", 0	
	exception				db "", 0
	security				db "", 0
	relocation				db "", 0	
	debug					db "", 0
	achitecrute				db "", 0
	reserved				db "", 0
	tls						db "", 0
	configuration			db "", 0
	boundimport				db "", 0
	iat						db "", 0
	delayimport				db "", 0
	dotnet					db "", 0
	
.code

HexToString PROC uses eax ebx ecx edx
	
	push	10h
	push	offset tmp
	call	RtlZeroMemory	
	
	
	xor 	ecx, ecx
	mov		ebx, offset tmp
	xor 	edx, edx
	xor		edi, edi
	lap:
		mov		edx, 0Fh
		and		edx, eax
		
		mov		dl, chuoi[edx]
		mov		[ebx], dl
		shr		eax, 4
		inc		ecx
		inc		ebx
		
		cmp		ecx, 8
		jb 		lap
	
	ret

ToHex endp


WriteDataToFile PROC uses eax ebx ecx edx, buffer:dword
	xor		eax, eax
	
	push	buffer
	call	lstrlen
	
	push	NULL
	push	0
	push	eax
	push	buffer
	push	hOutput
	call	WriteFile
	
	push	NULL
	push	0
	push	3h
	push	offset ente
	push	hOutput
	call	WriteFile
	
	ret

WriteDataToFile endp


start:
	push	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ
	push	GENERIC_READ
	push 	offset file	
	call	CreateFile
	mov		hFile, eax
	
	
	push	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ
	push	GENERIC_READ
	push 	offset output	
	call	CreateFile
	mov		hOutput, eax
	
	
	
	
end start

