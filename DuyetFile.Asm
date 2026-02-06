.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc
include shlwapi.inc

includelib kernel32.lib
includelib user32.lib
includelib shlwapi.lib


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
	ov					dd 20 dup(0)
	off					dd 0
	index				dd 0
	delta				dd 0
	namefunction 		db 128 dup(0)
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
	titIAT				db "------------------IAT------------------", 13, 10, 0
	iid						dd 5 dup(0)
	module_name				db "Module name: ", 0
	module_name_val			db 64 dup(0)
	ofts					db " | OFTs: ", 0
	timedatestamp			db " | TimeDateStamp: ", 0
	forwarderchain			db " | ForwarderChain: ", 0
	namerav					db " | Name RAV: ", 0
	fts						db " | FTs(IAT): ", 0
	
	hint					db "Hint: ", 0
	namefunc				db " | Name function: ", 0
	offs					dd 0
	ordinal					db " | Ordinal: ", 0
	na						db "N/A", 0
	itd						dd 0
	
	
	;--------------------------------------------------------------------
	titEAT					db "------------------EAT------------------", 13, 10, 0
	titTableEAT				db "---------------TABLE EAT---------------", 13, 10, 0
	ied						dd 10 dup(0)
	characteristics_exp		db "Characteristics: ", 0
	timedatestamp_exp		db "TimeDateStamp: ", 0
	majorversion			db "MajorVersion: ", 0
	minorversion			db "MinorVersion: ", 0
	name_exp				db "Name: ", 0
	nname					dd 0
	base					db "Base: ", 0
	nbase					dd 0
	numberoffunctions		db "NumberOfFunctions: ", 0
	nfunc					dd 0
	numberofnames			db "NumberOfNames: ", 0
	nName					dd 0
	addressoffunctions		db "AddressOfFunctions: ", 0
	addressofnames			db "AddressOfNames: ", 0
	addressofnameordinals	db "AddressOfNameOrdinal: ", 0
	ordinal_export			db "Ordinal: ", 0
	name_ordinal 			db " | Name Ordinal: ", 0
	func_rva				db " | Function RVA: ", 0
	name_rva				db " | Name RVA: ", 0
	name_exp_func			db " | Name: ", 0
	
	exp_func				dd 0
	exp_name				dd 0
	exp_ord					dd 0
	
	tmp_exp					dw 0
	ok						db 0
	func_rva_val			dd 0
	name_function_exp		db 128 dup(0)
	
	;----------------relocation-------------------------
	titReloc					db "------------------RELOCATION------------------", 13, 10, 0
	titTableReloc				db "---------------TABLE RELOCATION---------------", 13, 10, 0
	sizeReloc					dd 0
	start_reloc					dd 0
	rva_reloc							db "RVA: ", 0
	rva_val						dd 0
	sizeofblock					db " | Size Of Block: ", 0
	sizeofblock_val				dd 0
	items						db " | Items: ", 0
	items_val					dd 0
	item						db "Item: ", 0
	item_val					dw 0
	rva_item					db " | RVA: ", 0
	rva_item_val				dd 0
	typ							db " | Type: ", 0
	entry						dw 0
	items_dec					dd 0
	
	fmt           				db "%d",0
	bff		 					db 32 dup(0)
	
	absolute					db "ABSOLUTE",0
	highlow						db "HIGHLOW", 0
	highadj						db "HIGHADJ", 0
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

CheckOrdinal PROC uses ebx ecx edx, ind:dword
	xor 	eax, eax
	mov		eax, exp_ord
	mov		ecx, nName
	xor		edx, edx
	loop_check:
	
	mov		ebx, eax
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	push	ebx
	push	ecx
	push	edx
	
	push	offset ov
	push	NULL
	push	2
	push	offset tmp_exp
	push	hFile
	call	ReadFile
	
	xor		eax, eax
	mov		ax, tmp_exp
	cmp		eax, ind
	pop		edx
	je		done_check_ord
	inc		edx
	pop		ecx
	pop		eax
	add		eax, 2
	loop	loop_check
	xor 	bl, bl
	mov		bl, 0
	mov		ok, bl
	ret
	
	done_check_ord:
	xor 	bl, bl
	mov		bl, 1
	mov		ok, bl
	xor 	eax, eax
	mov		eax, edx
	ret

CheckOrdinal endp


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
	mov		eax, offset ov
	add		eax, 8h
	xor		ebx, ebx
	mov		ebx, 60
	mov		dword ptr [eax], ebx
	
	
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
	xor		ebx, ebx
	mov		ebx, off
	
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
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
	mov		ebx, off
	add		ebx, 14h
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	
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
	mov		ebx, off
	add		ebx, 1ch
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
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
	mov		ebx, off
	add		ebx, 50h
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
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
	
	pop		ecx
	push	ecx
	cmp		ecx, 5
	je		get_size_reloc
	jne		continue_read		
	get_size_reloc:
	xor		ecx, ecx
	mov		ecx, dword ptr data
	mov		sizeReloc, ecx
	continue_read:
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
	
	push	offset titIAT
	call	WriteTitleToFile
	
	xor		edx, edx
	mov		edx, rva_import
	cmp		edx, 0
	je		done_iat
	
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
	
	
	mov		offs, eax
	
	read_image_import_descriptor:
	
	xor		ebx, ebx
	mov		ebx, offs
	
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	add		ebx, 14h
	mov		offs, ebx
	 
	push 	offset ov
	push	NULL
	push	14h
	push	offset iid
	push	hFile
	call 	ReadFile
	
	xor		eax, eax
	mov		eax, offset iid
	add 	eax, 0ch
	mov		eax, dword ptr [eax]
	xor 	ebx, ebx
	cmp		ebx, eax
	je		done_iat
	;module_name
	xor		eax, eax
	mov		eax, offset iid
	add 	eax, 0ch
	mov		eax, dword ptr [eax]
	
	sub		eax, delta
	xor		ebx, ebx
	mov		ebx, eax
	
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx

	
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
	mov		eax, offset iid
	add 	eax, 0h
	mov		eax, dword ptr [eax]
	
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
	mov		eax, offset iid
	add 	eax, 4h
	mov		eax, dword ptr [eax]
	
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
	mov		eax, offset iid
	add 	eax, 8h
	mov		eax, dword ptr [eax]
	
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
	mov		eax, offset iid
	add 	eax, 0ch
	mov		eax, dword ptr [eax]
	
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
	mov		eax, offset iid
	add 	eax, 10h
	mov		eax, dword ptr [eax]
	
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
	
	xor		ebx, ebx
	mov		ebx, dword ptr [iid]
	sub		ebx, delta
	
	read_array_itd:
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	push	ebx
	
	push	offset ov
	push	0
	push	4
	push	offset itd
	push	hFile
	call	ReadFile
	
	xor		eax, eax
	cmp		eax, itd
	je		done_read_image_import_descriptor
	
	;ordinal
	xor		eax, eax
	mov		eax, dword ptr itd
	xor		ebx, ebx
	mov		ebx, 80000000h
	and		ebx, eax
	cmp		ebx, 00000000h
	je		read_addressofdata
	mov		dword ptr data, eax
	
	xor		eax, eax
	mov		eax, dword ptr na
	
	mov		dword ptr tmp, eax		
	
	push	offset tmp
	push	offset hint
	call	WriteDataToFileInLine
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset ordinal
	call	WriteDataToFile
	
	xor		ebx, ebx
	pop		ebx
	add		ebx, 4
	jmp		read_array_itd
	
	read_addressofdata:
	xor		eax, eax
	mov		eax, dword ptr itd
	sub		eax, delta
	mov		ebx, eax
	;doc va ghi hint
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx

	push	offset ov
	push	0
	push	2
	push	offset data
	push	hFile
	call	ReadFile
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset hint
	call	WriteDataToFileInLine
	
	push	NULL
	push	0
	push	128
	push	offset namefunction
	push	hFile
	call	ReadFile
	
	push	offset namefunction
	push	offset namefunc
	call	WriteDataToFile
	
	xor		ebx, ebx
	pop		ebx
	add		ebx, 4
	jmp		read_array_itd
	
	done_read_image_import_descriptor:
	push	14h
	push	offset iid
	call 	RtlZeroMemory
	
	jmp		read_image_import_descriptor
	
	done_iat:
	;EAT------------------------------------------------------------------------------------------
	push	offset titEAT
	call	WriteTitleToFile
	
	xor		edx, edx
	mov		edx, rva_export
	cmp		edx, 0
	je		h_ordinal
	
	xor		edx, edx
	xor 	ecx, ecx
	mov		cx, numberofsectionsval
	mov		edx, offset arr_section
	
	loop_find_section_eat:
	
	xor 	eax, eax
	mov		eax, rva_export
	xor		ebx, ebx
	mov		ebx, dword ptr [edx]
	
	cmp		eax, ebx
	jae		next_section_eat
	jb		finded_eat
	next_section_eat:
	add		edx, 8
	loop	loop_find_section_eat
	finded_eat:
	mov		eax, offset export_section
	sub		edx, 8
	xor		ecx, ecx
	mov		ecx, [edx]
	mov		[eax], ecx
	
	mov		ecx, [edx+4]
	mov		[eax+4], ecx
	
	;tinh file offset cua image import discriptor
	
	xor		eax, eax
	mov		eax, rva_export
	
	xor		ebx, ebx
	mov		ebx, dword ptr export_section
	
	;sub		eax, ebx
	
	xor		ecx, ecx
	mov		ecx, offset export_section
	add		ecx, 4
	mov		ecx, [ecx]
	sub		ebx, ecx
	mov		delta, ebx
	sub		eax, ebx
	
	
	mov		offs, eax
	mov		ebx, eax
	
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	push	offset ov
	push	NULL
	push	28h
	push	offset ied
	push	hFile
	call	ReadFile
	
	;Characteristics
	mov		eax, dword ptr ied
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset characteristics_exp
	call	WriteDataToFile
	
	;TimeDateStamp_exp
	mov		eax, offset ied
	add		eax, 4h
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset timedatestamp_exp
	call	WriteDataToFile
	
	;MajorVersion
	
	mov		eax, offset ied
	add		eax, 8h
	mov		eax, dword ptr [eax]
	mov		word ptr data, ax
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset majorversion
	call	WriteDataToFile
	
	;MinorVersion
	
	mov		eax, offset ied
	add		eax, 8h
	mov		eax, dword ptr [eax]
	shr		eax, 16
	mov		word ptr data, ax
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset minorversion
	call	WriteDataToFile
	
	;nname
	mov		eax, offset ied
	add		eax, 0ch
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset name_exp
	call	WriteDataToFile
	
	;nbase
	mov		eax, offset ied
	add		eax, 10h
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	mov		nbase, eax
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset base
	call	WriteDataToFile
	
	;numberoffunc
	mov		eax, offset ied
	add		eax, 14h
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	mov		nfunc, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset numberoffunctions
	call	WriteDataToFile
	;numberofnames
	mov		eax, offset ied
	add		eax, 18h
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	mov		nName, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset numberofnames
	call	WriteDataToFile
	
	;addressoffunctions
	mov		eax, offset ied
	add		eax, 1ch
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	sub		eax, delta
	mov		exp_func, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset addressoffunctions
	call	WriteDataToFile

	;addressofnames
	mov		eax, offset ied
	add		eax, 20h
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	sub		eax, delta
	mov		exp_name, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset addressofnames
	call	WriteDataToFile
	
	;addressofnameordinals
	mov		eax, offset ied
	add		eax, 24h
	mov		eax, dword ptr [eax]
	mov		dword ptr data, eax
	sub		eax, delta
	mov		exp_ord, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call	Reverse
	
	push	offset tmp
	push	offset addressofnameordinals
	call	WriteDataToFile
	;----------------------
	push	offset titTableEAT
	call  	WriteTitleToFile
	
	xor		ecx, ecx
	xor		edx, edx
	mov		edx, exp_func
	;for addresoffunction {if index_iat in index_iot: get value_in_index_iot else ok = 0 }
	
	loop_addressoffunctions:
	push	ecx
	
	;---------------------
	
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], edx
	
	push	edx
	
	push	offset ov
	push 	NULL
	push	4
	push	offset func_rva_val
	push	hFile
	call	ReadFile
	
	xor		edx, edx
	mov		edx, func_rva_val
	
	cmp		edx, 00000000h
	je		set_value
	
	
	xor		eax, eax
	mov		eax, nbase
	
	add		eax, ecx
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset ordinal_export
	call	WriteDataToFileInLine
	
	mov		dword ptr data, edx
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset func_rva
	call	WriteDataToFileInLine
	
	;-------------------------
	
	xor		ecx, ecx
	pop		edx
	pop		ecx
	push	ecx
	push	edx
	
	
	push	ecx
	call	CheckOrdinal
	
	xor		ebx, ebx
	mov		bl, 1
	cmp		ok, bl
	mov		ok, bh
	jne		dont_ordinal
	
	mov		index, eax
	mov		ebx, 2
	mul		ebx
	
	mov		ebx, exp_ord
	add		ebx, eax
	
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	push 	offset ov
	push	0
	push	2
	push	offset data
	push	hFile
	call	ReadFile
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset name_ordinal
	call	WriteDataToFileInLine
	
	mov		eax, index
	mov		ebx, 4
	mul		ebx
	
	mov		ebx, exp_name
	add		ebx, eax
	
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	push 	offset ov
	push	0
	push	4
	push	offset data
	push	hFile
	call	ReadFile
	
	mov		eax, dword ptr data
	push	eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset name_rva
	call	WriteDataToFileInLine
	
	
	pop		eax
	sub		eax, delta
	mov		ebx, eax
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	push 	offset ov
	push	0
	push	128
	push	offset name_function_exp
	push	hFile
	call	ReadFile
	
	push	offset name_function_exp
	push	offset name_exp_func
	call	WriteDataToFile
	
	jmp		set_value
	
	dont_ordinal:
	xor		eax, eax
	mov		eax, dword ptr na
	mov		dword ptr tmp, eax	
	push	offset tmp
	push	offset name_ordinal
	call	WriteDataToFileInLine
	xor		eax, eax
	mov		eax, dword ptr na
	mov		dword ptr tmp, eax	
	push	offset tmp
	push	offset name_rva
	call	WriteDataToFileInLine
	xor		eax, eax
	mov		eax, dword ptr na
	mov		dword ptr tmp, eax	
	push	offset tmp
	push	offset name_exp_func
	call	WriteDataToFile
	
	set_value:
	pop		edx
	add		edx, 4
	pop		ecx
	inc		ecx
	cmp		ecx, nfunc
	jae		h_ordinal
	jmp 	loop_addressoffunctions
	
	h_ordinal:
	
	;---------------relocation-------------------
	
	push	offset titReloc
	call	WriteTitleToFile
	
	xor		edx, edx
	mov		edx, rva_relocation
	cmp		edx, 0
	je		done_end
	
	xor		edx, edx
	xor 	ecx, ecx
	mov		cx, numberofsectionsval
	mov		edx, offset arr_section
	
	loop_find_section_reloc:
	
	xor 	eax, eax
	mov		eax, rva_relocation
	xor		ebx, ebx
	mov		ebx, dword ptr [edx]
	
	cmp		eax, ebx
	jae		next_section_reloc
	jb		finded_reloc
	next_section_reloc:
	add		edx, 8
	loop	loop_find_section_reloc
	finded_reloc:
	mov		eax, offset relocation_section
	sub		edx, 8
	xor		ecx, ecx
	mov		ecx, [edx]
	mov		[eax], ecx
	mov		ecx, [edx+4]
	mov		[eax+4], ecx
	;tinh file offset cua image import discriptor
	xor		eax, eax
	mov		eax, rva_relocation
	xor		ebx, ebx
	mov		ebx, dword ptr relocation_section
	;sub		eax, ebx
	xor		ecx, ecx
	mov		ecx, offset relocation_section
	add		ecx, 4
	mov		ecx, [ecx]
	sub		ebx, ecx
	mov		delta, ebx
	sub		eax, ebx
	mov		offs, eax
	mov		start_reloc, eax
	xor		eax, eax
	
	
	loop_read_reloc:
	
	push	eax
	xor		eax, eax
	mov		eax, start_reloc
	mov		ebx, eax
	mov		eax, offset ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	push 	offset ov
	push	NULL
	push	4
	push	offset rva_val
	push	hFile
	call	ReadFile
	
	xor		eax, eax
	mov		eax, dword ptr rva_val
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset rva_reloc
	call	WriteDataToFileInLine
	
	push 	NULL
	push	NULL
	push	4
	push	offset sizeofblock_val
	push	hFile
	call	ReadFile
	
	xor		eax, eax
	mov		eax, dword ptr sizeofblock_val
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset sizeofblock
	call	WriteDataToFileInLine
	
	xor		eax, eax
	mov		eax, sizeofblock_val
	sub		eax, 8
	shr		eax, 1
	mov		items_val, eax
	
	 
	push	eax
	push	offset fmt
	push	offset bff
	call	wsprintf
	add 	esp, 12
	
	push	offset bff
	push	offset items
	call	WriteDataToFile
	
	xor		ecx, ecx
	mov		ecx, items_val
	loop_read_entry:
	push	ecx
	
	push 	NULL
	push	NULL
	push	2
	push	offset item_val
	push	hFile
	call	ReadFile
	
	xor		eax, eax
	mov		ax, word ptr item_val
	mov		word ptr data, ax
	
	push	2h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 2h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset item
	call	WriteDataToFileInLine
	
	xor		eax, eax
	mov		eax, rva_val
	xor		ebx, ebx
	mov		bx, item_val
	and		bx, 0fffh
	
	add		eax, ebx
	mov		dword ptr data, eax
	
	push	4h
	call	HexToString
	
	xor		ecx, ecx
	mov		ecx, 4h
	push	offset tmp
	call 	Reverse
	
	push	offset tmp
	push	offset rva_item
	call	WriteDataToFileInLine
	
	mov		bx, item_val
	and		bx, 0f000h
	
	cmp		bx, 0
	je		_absolute
	cmp		bx, 03000h
	je		_highlow
	cmp		bx, 04000h
	je		_highadj	
	jne		_na
	_absolute:
	push	offset absolute
	push	offset tmp
	call	lstrcpy
	
	push	offset tmp
	push	offset typ
	call	WriteDataToFile
	jmp		done_loop_read_entry
	_highlow:
	push	offset highlow
	push	offset tmp
	call	lstrcpy
	
	push	offset tmp
	push	offset typ
	call	WriteDataToFile
	jmp		done_loop_read_entry
	_highadj:
	
	push	offset highadj
	push	offset tmp
	call	lstrcpy
	
	push	offset tmp
	push	offset typ
	call	WriteDataToFile
	jmp		done_loop_read_entry
	_na:
	push	offset na
	push	offset tmp
	call	lstrcpy
	
	push	offset tmp
	push	offset typ
	call	WriteDataToFile
	jmp		done_loop_read_entry
	
	done_loop_read_entry:
	xor		ecx, ecx
	pop		ecx
	dec		ecx
	cmp		ecx, 0
	ja		loop_read_entry
	
	
	xor		ebx, ebx
	mov		ebx, start_reloc
	add		ebx, sizeofblock_val
	mov		start_reloc, ebx
	
	xor		eax, eax
	pop		eax
	add		eax, sizeofblock_val
	xor		ebx, ebx
	mov		ebx, sizeReloc
	cmp		eax, ebx
	jb		loop_read_reloc
	done_end:
	push	hOutput
	call 	CloseHandle

	
	push	hFile
	call 	CloseHandle
	ret
end start

