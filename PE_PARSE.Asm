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
	data				db	16 dup(0)		
	tab					db 09h, 09h, 0
	ov					OVERLAPPED <>
	off					dd 0
	index				dd 0
	delta				dd 0
	
	;ten bien dung chung
	os					db "Offset: ", 0
	sz 					db " Size: ", 0
	rva					db "RVA: ", 0
	import_section		dd 2 dup(0)
	export_section		dd 2 dup(0)
	relocation_section	dd 2 dup(0)
	;ten bien trong pe
	;DOS Header
	titDos					db "----------------DOS HEADER--------------", 13, 10, 0
	e_magic 				db "e_magic: ", 0
	e_lfanew				db "e_lfanew: ", 0
	;PE Header
	titPEHeader				db "----------------PE HEADER---------------", 13, 10, 0
	signature 				db "Signature: ", 0
	;PE Header-File Header
	titPEHeaderFileHeader	db "--------PE HEADER - FILE HEADER---------", 13, 10, 0
	machine					db "Machine: ", 0
	numberofsections 		db "NumberOfSections: ", 0
	numberofsectionsval		dw 0
	sizeofoptionalheader 	db "SizeOfOptionalHeader: ", 0
	sizeofoptionalheaderval	dw 0
	characteristics			db "Characreristics: ", 0
	;PE Header-Optional Header
	titPEHeaderOptional		db "------PE HEADER - OPTIONAL HEADER-------", 13, 10, 0
	magic 					db "Magic: ", 0
	sizeofcode				db "SizeOfCode: ", 0
	sizeofinitializeddata	db "SizeOfInitializedData: ", 0
	sizeofUnitializeddata	db "SizeOfUnitializedData: ", 0
	addressofentrypoint		db "AddressOfEntryPoint; ", 0
	baseofcode				db "BaseOfCode: ", 0
	baseofdata				db "BaseOfData: ", 0
	imagebase				db "ImageBase: ", 0
	sectionalignment		db "SectionAlignment: ", 0
	filealignment			db "FileAlignment: ", 0
	sizeofimage				db "SizeOfImage: ", 0
	sizeofheader			db "SizeOfHeader: ", 0
	;title directori
	titDatadirectory		db "------------DATA DIRECTORIES------------", 13, 10, 0
	
	export					db "export: ", 0
	import					db "import: ", 0
	resource				db "resource: ", 0	
	exception				db "exception: ", 0
	security				db "security: ", 0
	relocation				db "relocation: ", 0	
	debug					db "debug: ", 0
	achitecrute				db "achitecrute: ", 0
	reserved				db "reserved: ", 0
	tls						db "tls: ", 0
	configuration			db "configuration: ", 0
	boundimport				db "boundimport: ", 0
	iat						db "iat: ", 0
	delayimport				db "delayimport: ", 0
	dotnet					db "dotnet: ", 0
	
	rva_import				dd 0
	rva_export				dd 0
	rva_relocation			dd 0
	
	arr						dd offset export, offset import, offset resource, offset exception, offset security, offset relocation, offset debug,  offset achitecrute, offset reserved, offset tls, offset configuration, offset boundimport,offset iat ,offset delayimport, offset dotnet
	;--------------------------------------------------------------------
	;section
	titSection				db "---------------SECTIONS---------------", 13, 10, 0
	name_sec				db "Name: ", 0
	virtualsize				db " | Virtual Size: ", 0
	virtualaddress			db " | Virtual Address: ", 0
	rawsize					db " | Raw Size: ", 0
	rawaddress				db " | Raw Address: ", 0
	characteristics_sec		db " | Characteristics: ", 0
	tmp_section				db 40 dup(0)
	arr_section				dd 32 dup(0)
	;----------------------------------------------------------------------
	iid						IMAGE_IMPORT_DESCRIPTOR <>
	module_name				db "Module name: ", 0
	module_name_val			db 64 dup(0)
	ofts					db "OFTs: ", 0
	timedatestamp			db "TimeDateStamp: ", 0
	forwarderchain			db "ForwarderChain: ", 0
	namerav					db "Name RAV: ", 0
	fts						db "FTs(IAT): ", 0
	
	hint					db "Hint: ", 0
	namefunc				db "Name function: ", 0
	
.code

HexToString PROC uses eax ebx ecx edx, count:dword
	
	push	10h
	push	offset tmp
	call	RtlZeroMemory	
	
	mov		eax, dword ptr data
	
	xor 	ecx, ecx
	mov		ebx, offset tmp
	xor 	edx, edx
	mov		edi, count
	lap:
		mov		edx, 0Fh
		and		edx, eax
		mov		dl, chuoi[edx]
		mov		[ebx+1], dl
		shr		eax, 4
		
		mov		edx, 0Fh
		and		edx, eax
		mov		dl, chuoi[edx]
		mov		[ebx], dl
		shr		eax, 4
		
		inc		ecx
		add		ebx, 2
		
		cmp		ecx, edi
		jb 		lap
	
	push	10h
	push	offset data
	call	RtlZeroMemory
	ret

HexToString endp

Reverse PROC uses eax ebx ecx edx, buffer: dword
	xor 	edx, edx
	mov		ebx, buffer
	laprever:
	xor		eax, eax
	mov		al, byte ptr [ebx]
	inc 	ebx
	mov		ah, byte ptr [ebx]
	inc		ebx
	inc		edx
	push	eax
	loop 	laprever
	
	mov		ebx, buffer
	xor 	ecx, ecx
	mov		ecx, edx
	lapreverout:
	pop		eax
	mov		[ebx], ax
	add		ebx, 2
	
	loop	lapreverout
	
	ret

Reverse endp


WriteDataToFile PROC uses eax ebx ecx edx, til:dword, buffer:dword
	xor		eax, eax
	
	push	til
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	til
	push	hOutput
	call	WriteFile
	
	push	buffer
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	buffer
	push	hOutput
	call	WriteFile
	
	push	NULL
	push	NULL
	push	2h
	push	offset ente
	push	hOutput
	call	WriteFile
	
	push	16
	push	buffer
	call 	RtlZeroMemory
	
	ret

WriteDataToFile endp

WriteTitleToFile PROC titl: dword
	
	push	titl
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	titl
	push	hOutput
	call	WriteFile
	
	ret

WriteTitleToFile endp


WriteDataToFileInLine PROC uses eax ebx ecx edx, til:dword, buffer:dword
	xor		eax, eax
	
	push	til
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	til
	push	hOutput
	call	WriteFile
	
	push	buffer
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	buffer
	push	hOutput
	call	WriteFile
	
	push	16
	push	buffer
	call 	RtlZeroMemory
	
	ret

WriteDataToFileInLine endp

WriteDataToFileInLineByNumber PROC uses eax ebx ecx edx, til:dword, buffer:dword
	xor		eax, eax
	
	push	til
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	til
	push	hOutput
	call	WriteFile
	
	push	buffer
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	buffer
	push	hOutput
	call	WriteFile
	
	push	64
	push	buffer
	call 	RtlZeroMemory
	
	ret

WriteDataToFileInLineByNumber endp



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
	push	CREATE_ALWAYS
	push	NULL
	push	FILE_SHARE_READ or FILE_SHARE_WRITE
	push	GENERIC_READ or GENERIC_WRITE
	push 	offset output	
	call	CreateFile
	mov		hOutput, eax
	
	;title DOS
	push	offset titDos
	call	WriteTitleToFile
	
	;chu ky MZ
	push	NULL
	push	NULL
	push	2
	push	offset data
	push	hFile
	call 	ReadFile
	
	push	offset data
	push	offset e_magic
	call	WriteDataToFile
	
	;e_lfanew
	mov		ov.loffset, 60
	mov		ov.OffsetHigh, 0
	
	push	offset ov
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	xor		eax, eax
	mov		eax, dword ptr data
	mov		off, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset e_lfanew
	call	WriteDataToFile
	
	;title pe header
	push	offset titPEHeader
	call	WriteTitleToFile
	
	;signature PE
	xor		eax, eax
	mov		eax, off
	mov		ov.loffset, eax
	
	push	offset ov
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	 
	push	offset data
	push	offset signature
	call	WriteDataToFile
	
	;title file header
	
	push	offset titPEHeaderFileHeader
	call	WriteTitleToFile
	
	;Machine
	push	NULL
	push	NULL
	push	2
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset machine
	call	WriteDataToFile
	
	;NumberOfSection
	push	NULL
	push	NULL
	push	2
	push	offset data
	push	hFile
	call 	ReadFile
	
	xor		eax, eax
	mov		ax,word ptr data
	mov		numberofsectionsval, ax
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset numberofsections
	call	WriteDataToFile
	
	;sizeofoptionalheader
	mov		eax, off
	add		eax, 14h
	mov		ov.loffset, eax
	
	push	offset ov
	push	NULL
	push	2
	push	offset data
	push	hFile
	call 	ReadFile
	
	xor		eax, eax
	mov		ax, word ptr data
	mov		sizeofoptionalheaderval, ax
	

	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset sizeofoptionalheader
	call	WriteDataToFile
	
	;characteristics
	push	NULL
	push	NULL
	push	2
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset characteristics
	call	WriteDataToFile
	;title Optional header-------------------------------------------------------
	
	push	offset titPEHeaderOptional
	call	WriteTitleToFile
	
	;Magic
	push	NULL
	push	NULL
	push	2
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset magic
	call	WriteDataToFile
	
	;sizeofcode
	mov		eax, off
	add		eax, 1ch
	mov		ov.loffset, eax
	
	push	offset ov
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset sizeofcode
	call	WriteDataToFile
	
	;sizeofinitializeddata

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset sizeofinitializeddata
	call	WriteDataToFile
	
	;sizeofUnitializeddata

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset sizeofUnitializeddata
	call	WriteDataToFile
	
	;addressofentrypoint

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset addressofentrypoint
	call	WriteDataToFile
	
	;baseofcode

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset baseofcode
	call	WriteDataToFile
	
	;baseofdata

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset baseofdata
	call	WriteDataToFile
	
	;imagebase

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset imagebase
	call	WriteDataToFile
	
	;sectionalignment

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset sectionalignment
	call	WriteDataToFile
	
	;filealignment

	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset filealignment
	call	WriteDataToFile
	
	;sizeofimage
	mov		eax, off
	add		eax, 50h
	mov		ov.loffset, eax
	
	push	offset ov
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset sizeofimage
	call	WriteDataToFile
	
	;sizeofheader
	
	
	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;xor		eax, eax
	;mov		ax, word ptr data
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset sizeofheader
	call	WriteDataToFile
	
	;title Datadirectories-------------------------------------------------------
	
	push	offset titDatadirectory
	call	WriteTitleToFile
	
	mov		eax, off
	add		eax, 78h
	
	push	0
	push	0
	push	eax
	push	hFile
	call	SetFilePointer
	
	xor		ecx, ecx
	mov		ecx, 0
	;---------------------------------------------------------------
	read_directory:
	
	push	ecx
	
	xor		ebx, ebx
	mov		ebx, offset arr
	xor		eax, eax
	mov		eax, 4
	imul 	eax, ecx
	add		ebx, eax
	push	ebx
	
	push	[ebx]
	call	lstrlen
	
	pop		ebx
	
	push	NULL
	push	NULL
	push	eax
	push	[ebx]
	push	hOutput
	call	WriteFile
	
	;doc RVA
	push	NULL
	push	NULL
	push	5
	push	offset rva
	push	hOutput
	call	WriteFile
	
	
	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	;if index = 0 | index = 1 | index = 5 {lay rva} else {bo qua}
	
	xor		ecx, ecx
	pop		ecx
	push	ecx
	cmp		ecx, 0
	je		index0
	cmp		ecx, 1
	je		index1
	cmp		ecx, 5
	je		index5
	jmp		tiep
	index0:
	xor		ecx, ecx
	mov		ecx, dword ptr data
	mov		rva_export, ecx
	jmp 	tiep
	index1:
	xor		ecx, ecx
	mov		ecx, dword ptr data
	mov		rva_import, ecx
	jmp 	tiep
	index5:
	xor		ecx, ecx
	mov		ecx, dword ptr data
	mov		rva_relocation, ecx
	jmp 	tiep
	
	
	
	tiep:
	push	4
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	call	lstrlen
	
	
	push	NULL
	push	NULL
	push	eax
	push	offset tmp
	push	hOutput
	call	WriteFile
	
	push	16
	push	offset tmp
	call 	RtlZeroMemory
	
	;doc size
	push	NULL
	push	NULL
	push	7
	push	offset sz
	push	hOutput
	call	WriteFile
	
	push	NULL
	push	NULL
	push	4
	push	offset data
	push	hFile
	call 	ReadFile
	
	push	4
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	call	lstrlen
	
	push	NULL
	push	NULL
	push	eax
	push	offset tmp
	push	hOutput
	call	WriteFile
	
	push	NULL
	push	NULL
	push	2h
	push	offset ente
	push	hOutput
	call	WriteFile
	
	push	16
	push	offset tmp
	call 	RtlZeroMemory
	
	pop 	ecx
	inc		ecx
	xor		ebx, ebx
	mov		ebx, 0fh
	cmp		ecx, ebx
	jb		read_directory
	
	;section
	push	offset titSection
	call	WriteTitleToFile
	
	xor		ecx, ecx
	mov		ecx, off
	add		ecx, 18h
	xor		eax, eax
	mov		ax, sizeofoptionalheaderval
	add		ecx, eax
	
	push	0
	push	0
	push	ecx
	push	hFile
	call	SetFilePointer 
	
	xor		eax, eax
	mov 	eax, offset arr_section
	mov		index, eax
	
	xor		ecx, ecx
	mov		cx, numberofsectionsval
	
	read_section:
	
	push	ecx
	
	push	NULL
	push	NULL
	push	40
	push	offset tmp_section
	push	hFile
	call 	ReadFile
	
	push	8
	push	offset tmp_section
	push	offset tmp
	call 	lstrcpyn
	
	push	offset tmp
	push	offset name_sec
	call	WriteDataToFileInLine
	
	mov		eax, offset tmp_section
	;vitual size
	add		eax, 8
	push	eax
	
	push	4
	push	eax
	push	offset data
	call 	lstrcpyn
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset virtualsize
	call	WriteDataToFileInLine
	xor		eax, eax
	pop		eax
	
	;virtualaddress
	add		eax, 4
	push	eax
	
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	
	xor 	ecx, ecx
	mov		ecx, index
	mov		[ecx], eax
	add		ecx, 4
	mov		index, ecx
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset virtualaddress
	call	WriteDataToFileInLine
	xor		eax, eax
	pop		eax
	;rawsize
	add		eax, 4
	push	eax
	
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset rawsize
	call	WriteDataToFileInLine
	xor		eax, eax
	pop		eax
	;rawaddress
	add		eax, 4
	push	eax
	
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	
	xor 	ecx, ecx
	mov		ecx, index
	mov		[ecx], eax
	add		ecx, 4
	mov		index, ecx
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset rawaddress
	call	WriteDataToFileInLine
	xor		eax, eax
	pop		eax
	;characteristics_sec
	add		eax, 16
	push	eax
	
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset characteristics_sec
	call	WriteDataToFile
	
	xor		eax, eax
	pop		eax
	xor		ecx, ecx
	pop		ecx
	dec		ecx
	cmp		ecx, 0
	jne 	read_section
	
	
	;IAT------------------------------------------------------
	xor		edx, edx
	xor 	ecx, ecx
	mov		cx, numberofsectionsval
	mov		edx, offset arr_section
	
	loop_find_section:
	
	xor 	eax, eax
	mov		eax, rva_import
	xor		ebx, ebx
	mov		ebx, dword ptr [edx]
	
	cmp		eax, ebx
	jae		next_section
	jb		finded
	next_section:
	add		edx, 8
	loop	loop_find_section
	finded:
	mov		eax, offset import_section
	sub		edx, 8
	xor		ecx, ecx
	mov		ecx, [edx]
	mov		[eax], ecx
	
	mov		ecx, [edx+4]
	mov		[eax+4], ecx
	
	;tinh file offset cua image import discriptor
	
	xor		eax, eax
	mov		eax, rva_import
	
	xor		ebx, ebx
	mov		ebx, dword ptr import_section
	
	;sub		eax, ebx
	
	xor		ecx, ecx
	mov		ecx, offset import_section
	add		ecx, 4
	mov		ecx, [ecx]
	sub		ebx, ecx
	mov		delta, ebx
	sub		eax, ebx
	
	
	push	0
	push	0
	push	eax
	push	hFile
	call	SetFilePointer
	
	read_image_import_descriptor:
	
	push 	NULL
	push	NULL
	push	14h
	push	offset iid
	push	hFile
	call 	ReadFile
	
	mov		eax, iid.Name1
	xor 	ebx, ebx
	cmp		ebx, eax
	je		done
	;module_name
	xor		eax, eax
	mov		eax, iid.Name1
	sub		eax, delta
	
	mov		ov.loffset, eax
	
	push 	offset ov
	push	NULL
	push	64
	push	offset module_name_val
	push	hFile
	call 	ReadFile
	
	push	offset module_name_val
	push	offset module_name
	call	WriteDataToFileInLineByNumber
	;ofts
	xor		eax, eax
	mov		eax, iid.OriginalFirstThunk
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset ofts
	call	WriteDataToFileInLine
	;TimeDatestamp
	xor		eax, eax
	mov		eax, iid.TimeDateStamp
	mov		dword ptr data, eax
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset timedatestamp
	call	WriteDataToFileInLine
	;Forwarderchain
	xor		eax, eax
	mov		eax, iid.ForwarderChain
	mov		dword ptr data, eax
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset forwarderchain
	call	WriteDataToFileInLine
	
	;name1
	xor		eax, eax
	mov		eax, iid.Name1
	mov		dword ptr data, eax
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset forwarderchain
	call	WriteDataToFileInLine
	
	;fts
	xor		eax, eax
	mov		eax, iid.FirstThunk
	mov		dword ptr data, eax
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset fts
	call	WriteDataToFile
	
	push	14h
	push	offset iid
	call 	RtlZeroMemory
	
	jmp		read_image_import_descriptor
	
	done:
	ret
	
end start

