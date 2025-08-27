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
signature_str db "signature: ", 0
signature dd ?




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
	
	push	4
	push	offset address
	push	offset w_buffer
	push	titl
	push	hFile
	call 	WriteInFile
	
	ret

PrintHexWord ENDP

WriteInFile PROC hFile:dword, titl:dword, value:dword, ost:dword, sz:dword
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

PrintHexDword PROC uses eax ebx ecx edx,hFile:dword, titl:dword, w:dword, ost:dword

	mov 	ebx, w
	mov 	eax, dword ptr [ebx]
	mov 	ecx, 8
	lea 	edi, dw_buffer
	
next_nible1:
	xor		ebx, ebx
	rol 	eax, 4
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
	
	push	8
	push	offset address
	push	offset dw_buffer
	push	titl
	push	hFile
	call 	WriteInFile
	
	ret

PrintHexDword ENDP

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
	
	push	0
	push	0
	push	ecx
	push 	dword ptr [hFileOutput]
	call 	SetFilePointer
	
	push	0
	push	0
	push	4
	push 	offset e_lfanew
	push	dword ptr [hFileInput]
	call 	ReadFile

	mov 	ebx,dword ptr [e_lfanew]
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
	
	mov		ebx, ecx
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
	push	dword ptr [hFileOutput]
	call 	SetFilePointer
	
	xor 	eax, eax
	push 	offset e_lfanew_str
	call 	lstrlen
	
	push 	0
	push	0
	push	eax
	push	offset e_lfanew_str
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	7
	push 	offset offs
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	8
	push	offset address
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	2
	push	offset space
	push	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	6
	push	offset val
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	8
	push	offset dw_buffer
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
	push 	0
	push	0
	push	2
	push	offset crlf
	push 	dword ptr [hFileOutput]
	call 	WriteFile
	
end start








