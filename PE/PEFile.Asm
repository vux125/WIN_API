.386
.model flat, stdcall
option casemap:none

include  C:\masm32\include\windows.inc
include  C:\masm32\include\kernel32.inc
include  C:\masm32\include\user32.inc

includelib C:\masm32\lib\kernel32.lib
includelib C:\masm32\lib\user32.lib

.data

pathInput db "C:\Users\My Desktop\Documents\Malware\code\asm\PEFile\ipconfig.exe", 0
pathOutput db "C:\Users\My Desktop\Documents\Malware\code\asm\PEFile\output.txt", 0
hFileInput dd ?
hFileOutput dd ?

hexchar db "0123456789ABCDEF", 0
br db "------------------------------------------------------------------", 0
crlf db 0dh, 0ah
space db 20h,20h
w_buffer db 5 dup(0)
dw_buffer db 9 dup(0)

offs db "Offset=", 0
address db 9 dup(0)

val	db "Value=", 0


image_dos_header db "DOS HEADER",0
e_magic_str db "e_magic: ", 0
e_magic dw ?
e_cblp_str db "e_cblp: ", 0
e_cblp dw ?
e_cp_str db "e_cp: ", 0
e_cp dw ?
e_crlc_str db "e_crlc: ", 0
e_crlc dw ?
e_cparhdr_str db "e_cparhdr: ", 0
e_cparhdr dw ?
e_minalloc_str db "e_minalloc: ", 0
e_minalloc dw ?
e_maxalloc_str db "e_maxalloc: ", 0
e_maxalloc dw ?
e_ss_str db "e_ss: ", 0
e_ss dw ?
e_sp_str db "e_sp: ", 0
e_sp dw ?
e_csum_str db "e_csum: ", 0
e_csum dw ?
e_ip_str db "e_ip: ", 0
e_ip dw ?
e_cs_str db "e_cs: ", 0
e_cs dw ?
e_lfarlc_str db "e_lfarlc: ", 0
e_lfarlc dw ?
e_ovno_str db "e_ovno: ", 0
e_ovno dw ?
e_res_str db "e_res: ", 0
e_res dw 4 dup(?)
e_oemid_str db "e_oemid: ", 0
e_oemid dw ?
e_oeminfo_str db "e_oeminfo: ", 0
e_oeminfo dw ?
e_res2_str db "e_res2: ", 0
e_res2 dw 10 dup(?)
e_lfanew_str db "e_lfanew: ", 0
e_lfanew dd ?

image_nt_header db "PE HEADER", 0
start_pe_header dd ?

signature_str db "signature: ", 0
signature dd ?

fileHeader db "file_header:", 0dh, 0ah
Machine_str db "Machine: ", 0
Machine dw ?
NumberOfSections_str db "NumberOfSections: ", 0
NumberOfSections dw ? 
TimeDateStamp_str db "TimeDateStamp: ", 0
TimeDateStamp dd ?
PointerToSymbols_str db "PointerToSymbols: ", 0
PointerToSymbols dd ?
NumberOfSymbols_str db "NumberOfSymbols: ",0
NumberOfSymbols dd ?
SizeOfOptionalHeader_str db "SizeOfOptionalHeader: ", 0
SizeOfOptionalHeader dw ?
Characteristics_str db "Characteristics: ", 0
Characteristics dw ? 

optionalHeader db "optional_header:", 0dh, 0ah

Magic_str db "Magic: ", 0
Magic dw ?
AddressOfEntryPoint_str db "AddresOfEntryPoint: ", 0
AddressOfEntryPoint dd ?
ImageBase_str db "ImageBase: ", 0
ImageBase dq ? 
SectionAlignment_str db "SectionAlignment: ", 0
SectionAlignment dd ?
FileAlignment_str db "FileAlignment: ", 0 
FileAlignment dd ?
SizeOfImage_str db "SizeOfImage: ", 0
SizeOfImage dd ?
SizeOfHeader_str db "SizeOfHeader: ", 0
SizeOfHeader dd ?
dataDirectory_str db "Data Directory: ", 0dh, 0ah
dataDirectory dd 32 dup(0)

ExportTable_str db "ExportTable: (RVA-Size)",0dh, 0ah
ExportTableRVA       dd ?
ExportTableSize      dd ?

ImportTable_str db "ImportTable: (RVA-Size)", 0dh, 0ah
ImportTableRVA       dd ?
ImportTableSize      dd ?


sectionTable db "SECTION TABLE", 0dh, 0ah
SectionTable db 40 dup(0) 

tmp_b db ?
tmp_w dw ?
tmp_d dd ?
tmp_q dq ?
stt db "1", 0

Name_section db "Name: ", 0
VirtualSize_str db "Virtual Size: ", 0
VirtualAddress_str db "Virtual Address: ", 0
SizeOfRawData_str db "SizeOfRawData: ", 0
PointerToRawData_str db "PointerToRawData: ", 0
PointerToRelocations_str db "PointerToRelocations: ", 0
PointerToLinenumbers_str db "PointerToLinenumbers: ", 0
NumberOfRelocations_str  db "NumberOfRelocations: ",0
NumberOfLinenumbers_str db "NUmberOfLinenumbers: ",0
Characteristics_str_st db "Characteristics: ",0
 

.code

PrintHexWord PROC uses eax ebx ecx edx,hFile:dword, titl:dword, w:dword, ost:dword
	mov 	ebx, w
	mov 	ax, word ptr [ebx]
	mov 	ecx, 4
	lea 	edi, w_buffer
	
next_nible1:
	xor		ebx, ebx
	rol 	ax, 4
	mov 	bl, al
	and 	bl, 0fh
	mov 	dl,[hexchar + ebx]
	mov 	[edi], dl
	inc 	di
	loop 	next_nible1
	mov 	byte ptr [edi], 0
	
	
	mov		eax, ost
	mov 	ecx, 8
	lea 	edi, address
next_nible2:
	xor		ebx, ebx
	rol 	eax, 4
	mov 	bl, al
	and 	bl, 0fh
	mov 	dl,[hexchar + ebx]
	mov 	[edi], dl
	inc 	di
	loop 	next_nible2	
	mov 	byte ptr [edi], 0
	
	push 	2
	push	0
	push 	0
	push	hFile
	call 	SetFilePointer
	
	push	4
	push	offset address
	push	offset w_buffer
	push	titl
	push	hFile
	call 	WriteInFile
	
	ret

PrintHexWord ENDP

WriteInFile PROC uses ecx hFile:dword, titl:dword, value:dword, ost:dword, sz:dword
	xor 	eax, eax
	push 	titl
	call 	lstrlen
	
	push 	0
	push	0
	push	eax
	push	titl
	push 	hFile
	call 	WriteFile
	
	push 	0
	push	0
	push	7
	push 	offset offs
	push 	hFile
	call 	WriteFile
	
	push 	0
	push	0
	push	8
	push	ost
	push	hFile
	call 	WriteFile
	
	push 	0
	push	0
	push	2
	push	offset space
	push	hFile
	call 	WriteFile
	
	push 	0
	push	0
	push	6
	push	offset val
	push 	hFile
	call 	WriteFile
	
	
	push 	0
	push	0
	push	sz
	push	value
	push 	hFile
	call 	WriteFile
	
	push 	0
	push	0
	push	2
	push	offset crlf
	push 	hFile
	call 	WriteFile
	
	ret
WriteInFile endp

ReadByte PROC uses ecx edx, hFile:dword, root:dword, oset:dword, buffer:dword, sz:dword

	push 	root
	push	0
	push 	oset
	push	hFile
	call 	SetFilePointer
	
	
	push	0
	push	0
	push	sz
	push	buffer
	push	hFile
	call 	ReadFile

ret

ReadByte endp

PrintHexDword PROC uses ecx eax ebx edx edi, hFile:dword, titl:dword, d:dword, ost:dword
	
	mov 	ecx, d
	mov 	ebx, dword ptr [ecx]
	mov		eax, 0
	lea		edi, offset dw_buffer
	
next_nible:
	xor 	edx,edx
	rol		ebx, 4
	mov		dl, bl
	and 	dl, 0fh
	mov		dl, [hexchar + edx]
	mov 	[edi], dl
	inc		di
	inc		eax
	cmp 	eax, 8
	jne 	next_nible
	
	mov		ebx, ost
	mov 	eax, 0
	lea 	edi, offset address
next_nible2:
	xor		edx, edx
	rol 	ebx, 4
	mov 	dl, bl
	and 	dl, 0fh
	mov 	dl,[hexchar + edx]
	mov 	[edi], dl
	inc 	di
	inc		eax
	cmp 	eax, 8
	jne 	next_nible2	
	
	push 	2
	push	0
	push 	0
	push	hFile
	call 	SetFilePointer
	
	push	8
	push	offset address
	push	offset dw_buffer
	push	titl
	push	hFile
	call 	WriteInFile
	
	ret

PrintHexDword endp


SectionTables PROC uses eax ebx
	
	push	40
	push	offset SectionTable
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	
	; lay ten section

	mov 	eax, offset SectionTable
	mov 	edi, offset tmp_q
	mov		esi, dword ptr [eax]
	mov 	[edi], esi
	mov		esi, dword ptr [eax + 4]
	mov 	[edi+4], esi	
	
	xor		edx, edx 
	
	push 	0
	push	0
	push	2
	push	offset stt
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	2
	push	offset crlf
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	7
	push	offset Name_section
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	
	
	push	offset tmp_q
	call 	lstrlen
	
	push 	0
	push	0
	push	eax
	push	offset tmp_q
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	2
	push	offset crlf
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	;Virtual size
	pop 	ecx
	add		ecx, 8
	
	push	4
	push	offset tmp_d
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_d
	push	offset VirtualSize_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	;VirtualAddress
	add 	ecx, 4
	
	push	4
	push	offset tmp_d
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_d
	push	offset VirtualAddress_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	;SizeOfRawData
	
	add 	ecx, 4
	
	push	4
	push	offset tmp_d
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_d
	push	offset SizeOfRawData_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	;PointerToRawData
	add 	ecx, 4
	
	push	4
	push	offset tmp_d
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_d
	push	offset PointerToRawData_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	
	;PointerToRelocations
	add 	ecx, 4
	
	push	4
	push	offset tmp_d
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_d
	push	offset PointerToRelocations_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	;PointerToLinenumbers
	add 	ecx, 4
	
	push	4
	push	offset tmp_d
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_d
	push	offset PointerToLinenumbers_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	;NumberOfRelocations
	add 	ecx, 4
	
	push	2
	push	offset tmp_w
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_w
	push	offset NumberOfRelocations_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	
	;NumberOfLinenumbers
	add 	ecx, 2
	
	push	2
	push	offset tmp_w
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_w
	push	offset NumberOfLinenumbers_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	
	;Characteristics
	add 	ecx, 2
	
	push	4
	push	offset tmp_d
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset tmp_d
	push	offset Characteristics_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	add 	ecx, 4
	
	ret

SectionTables endp
;----------------------------------------------------------
start:	

	xor		eax, eax
	xor 	ebx, ebx
	xor 	ecx, ecx
	xor		edx, edx
	
	;mo file .exe
	push	0
	push	FILE_ATTRIBUTE_NORMAL
	push 	OPEN_EXISTING
	push	0
	push	FILE_SHARE_READ
	push	GENERIC_READ
	push	offset pathInput
	call 	CreateFile
	mov		dword ptr [hFileInput], eax
	
	
	;mo file input.txt
	push 	0
	push	FILE_ATTRIBUTE_NORMAL
	push	CREATE_ALWAYS
	push	0
	push	FILE_SHARE_WRITE
	push	GENERIC_WRITE
	push	offset pathOutput
	call 	CreateFile
	mov		dword ptr [hFileOutput], eax
	;----------------
	
	
	push	0
	push	0
	push	10
	push	offset image_dos_header
	push 	dword ptr [hFileOutput]
	call	WriteFile 	
	
	push 	0
	push	0
	push	2
	push	offset crlf
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	xor 	ecx, ecx
	
	;e_magic
	push	2
	push 	offset e_magic
	push	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	push	offset e_magic
	push	offset e_magic_str
	push	dword ptr [hFileOutput]
	call 	PrintHexWord
	
	add		ecx, 2
	
	;e_cblp
	
	push	2
	push	offset e_cblp
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_cblp
	push	offset e_cblp_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_cp
	
	push	2
	push	offset e_cp
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_cp
	push	offset e_cp_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_crlc
	
	push	2
	push	offset e_crlc
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_crlc
	push	offset e_crlc_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_cparhdr
	
	push	2
	push	offset e_cparhdr
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_cparhdr
	push	offset e_cparhdr_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	
	;e_minalloc
	
	push	2
	push	offset e_minalloc
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_minalloc
	push	offset e_minalloc_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_maxalloc
	
	push	2
	push	offset e_maxalloc
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_maxalloc
	push	offset e_maxalloc_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_ss
	
	push	2
	push	offset e_ss
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_ss
	push	offset e_ss_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_sp
	
	push	2
	push	offset e_sp
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_sp
	push	offset e_sp_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_csum
	
	push	2
	push	offset e_csum
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_csum
	push	offset e_csum_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_ip
	
	push	2
	push	offset e_ip
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_ip
	push	offset e_ip_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_cs
	
	push	2
	push	offset e_cs
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_cs
	push	offset e_cs_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_lfarlc
	
	push	2
	push	offset e_lfarlc
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_lfarlc
	push	offset e_lfarlc_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_ovno
	
	push	2
	push	offset e_ovno
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_ovno
	push	offset e_ovno_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_res[4]
	
	push	2
	push	offset e_res
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_res
	push	offset e_res_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	xor 	edx, edx
	mov 	ebx, offset e_res
e_res_arr:

	add		ebx, 2
	
	push	2
	push	ebx
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	ebx
	push	0
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add		ecx, 2
	inc		edx
	cmp		edx, 3
	jnz		e_res_arr		
	
	;e_oemid
	
	push	2
	push	offset e_oemid
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_oemid
	push	offset e_oemid_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2
	
	;e_oeminfo
	
	push	2
	push	offset e_oeminfo
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_oeminfo
	push	offset e_oeminfo_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2	
	
	;e_res2[10]
	
	push	2
	push	offset e_res2
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	offset e_res2
	push	offset e_res2_str
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add 	ecx, 2	
	xor 	edx, edx
	xor 	ebx, ebx
	mov 	ebx, offset e_res2
e_res2_arr:

	add		ebx, 2
	push	2
	push	ebx
	push 	ecx
	push	0
	push 	dword ptr [hFileInput]
	call 	ReadByte	
	
	push	ecx
	push 	ebx
	push	0
	push	dword ptr [hFileOutput]
	call	PrintHexWord
	
	add		ecx, 2
	inc		edx
	cmp		edx, 9
	jnz		e_res2_arr
	
	;e_lfanew
	
	
	push	4
	push	offset e_lfanew
	push	ecx
	push 	0
	push	dword ptr [hFileInput]
	call 	ReadByte

	push	ecx
	push	offset e_lfanew
	push	offset e_lfanew_str
	push	dword ptr [hFileOutput]
	call	PrintHexDword
	
	;----------------------------------------------------------------------	
	
	push	offset br
	call 	lstrlen
	
	push	0
	push	0
	push 	eax
	push	offset br
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	
	;PE_Header
	
	push	0
	push	0
	push 	2
	push	offset crlf
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push	0
	push	0
	push 	9
	push	offset image_nt_header
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push	0
	push	0
	push 	2
	push	offset crlf
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	;signature 4-byte
	
	mov 	ecx, dword ptr [e_lfanew]
	mov		[start_pe_header], ecx
	
	push	4
	push	offset signature
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset signature
	push	offset signature_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	;File header 20-byte
	
	push	0
	push	0
	push 	14
	push	offset fileHeader
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	mov 	ecx, dword ptr [start_pe_header]
	add		ecx, 4
	
	;machine
	
	push	2
	push	offset Machine
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset Machine
	push	offset Machine_str
	push	dword ptr [hFileOutput]
	call 	PrintHexWord
	
	add 	ecx, 2
	
	;NumberOfSections
	
	push	2
	push	offset NumberOfSections
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset NumberOfSections
	push	offset NumberOfSections_str
	push	dword ptr [hFileOutput]
	call 	PrintHexWord
	
	add 	ecx, 2
	
	;TimeDateStamp
	
	push	4
	push	offset TimeDateStamp
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset TimeDateStamp
	push	offset TimeDateStamp_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	add 	ecx, 4
	
	;PointerToSymbols
	
	push	4
	push	offset PointerToSymbols
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset PointerToSymbols
	push	offset PointerToSymbols_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	add 	ecx, 4
	
	;NumberOfSymbols
	
	push	4
	push	offset NumberOfSymbols
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset NumberOfSymbols
	push	offset NumberOfSymbols_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	add 	ecx, 4
	
	;SizeOfOptionalHeader
	
	push	2
	push	offset SizeOfOptionalHeader
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset SizeOfOptionalHeader
	push	offset SizeOfOptionalHeader_str
	push	dword ptr [hFileOutput]
	call 	PrintHexWord
	
	add 	ecx, 2
	
	;Characteristics
	
	push	2
	push	offset Characteristics
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset Characteristics
	push	offset Characteristics_str
	push	dword ptr [hFileOutput]
	call 	PrintHexWord
	
	;Optional header 224-byte (96-byte + 128-byte)
	
	push 	0
	push 	0
	push	18
	push 	offset optionalHeader
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	mov 	ecx, dword ptr [start_pe_header]
	add		ecx, 24
	
	;Magic
	
	push	2
	push	offset Magic
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset Magic
	push	offset Magic_str
	push	dword ptr [hFileOutput]
	call 	PrintHexWord
	
	add		ecx, 16
	
	;AddressEntryPoint
	
	push	4
	push	offset AddressOfEntryPoint
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset AddressOfEntryPoint
	push	offset AddressOfEntryPoint_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	add		ecx, 8
	;ImageBase
	
	push	8
	push	offset ImageBase
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte 
	
	
	add 	ecx, 8
	;SectionAlignment

	push	4
	push	offset SectionAlignment
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset SectionAlignment
	push	offset SectionAlignment_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	add		ecx, 4
	;FileAlignment
	
	push	4
	push	offset FileAlignment
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset FileAlignment
	push	offset FileAlignment_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	add		ecx, 20
	
	;SizeOfImage
	
	push	4
	push	offset SizeOfImage
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset SizeOfImage
	push	offset SizeOfImage_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	add 	ecx, 4
	
	;SizeOfHeader
	
	push	4
	push	offset SizeOfHeader
	push	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push 	ecx
	push	offset SizeOfHeader
	push	offset SizeOfHeader_str
	push	dword ptr [hFileOutput]
	call 	PrintHexDword
	
	
	;DataDirectory
	mov 	ecx, dword ptr [start_pe_header]
	add 	ecx, 24
	add		cx, word ptr [SizeOfOptionalHeader] 
	sub		ecx, 128
	
	push	128
	push	offset dataDirectory
	push 	ecx
	push	0
	push	dword ptr [hFileInput]
	call 	ReadByte
	
	push	ecx
	
	push	0
	push	0
	push	18
	push	offset dataDirectory_str
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push	0
	push	0
	push	25
	push	offset ExportTable_str
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	xor 	ecx, ecx
	pop 	ecx
	
	mov		eax, offset dataDirectory
	
	push	ecx
	push	eax
	push	0
	push	dword ptr [hFileOutput]	
	call 	PrintHexDword
	
	add		eax, 4
	add		ecx, 4
	
	push	ecx
	push	eax
	push	0
	push	dword ptr [hFileOutput]	
	call 	PrintHexDword
	
	
	add		ecx, 4
	push	ecx
	
	push	0
	push	0
	push	25
	push	offset ImportTable_str
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	xor		ecx, ecx
	pop 	ecx
	
	mov		eax, offset dataDirectory
	add		eax, 8
	
	push	ecx
	push	eax
	push	0
	push	dword ptr [hFileOutput]	
	call 	PrintHexDword
	
	add		ecx, 4
	add		eax, 4
	
	push	ecx
	push	eax
	push	0
	push	dword ptr [hFileOutput]	
	call 	PrintHexDword
	;-----------------------------------------------------------------
	;Section table
	
	push	offset br
	call 	lstrlen
	
	push	0
	push	0
	push 	eax
	push	offset br
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push	0
	push	0
	push 	2
	push	offset crlf
	push	dword ptr [hFileOutput]
	call 	WriteFile
		
	push	0
	push	0
	push	15
	push	offset sectionTable
	push 	dword ptr [hFileOutput]
	call	WriteFile 	
	
	;lay dia chi 
	
	mov 	ecx, dword ptr [start_pe_header]
	add		ecx, 24
	add		cx, word ptr [SizeOfOptionalHeader]
	
	xor 	eax, eax
	
	mov 	eax, dword ptr [stt]
	mov 	ebx, dword ptr [NumberOfSections]
	add		ebx, '0'
	
	sectionintable:
		call	SectionTables
		inc 	eax
		mov 	[stt], al
		cmp		al, bl
		jbe		sectionintable
end start
