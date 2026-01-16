.386
.model flat, stdcall
option casemap:none


include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib


.data
	fileName1 db "C:\Users\vutv\Downloads\RadASM-2.2.2.4-FullPackage\Masm\Projects\songuyento\SoThuNhat.txt", 0
	so1 dd 0
	buffer1 dd 0
	pos1 dw -4h
	
	fileName2 db "C:\Users\vutv\Downloads\RadASM-2.2.2.4-FullPackage\Masm\Projects\songuyento\SoThuHai.txt", 0
	so2 dd 0
	buffer2 dd 0
	pos2 dw -4h
	
	fileName3 db "C:\Users\vutv\Downloads\RadASM-2.2.2.4-FullPackage\Masm\Projects\songuyento\Tong.txt", 0
	
	hFile1 dd 0
	hFile2 dd 0
	hFileResult dd 0
	
	size1 dw 0
	size2 dw 0
	
	cx1	dw 4
	cx2 dw 4
	
	nho db 0
	tmp db 4 dup(0)
	
	ini dd "0000"
.code

Tong PROC uses ebx ecx

	
	mov 	edi, offset tmp
	
	xor		edx, edx
	mov 	edx, 3
	
	cmp 	dl, 0
	jb		doneLoop
	
	tinhtong:
	
	rol		ebx, 8
	cmp 	bl, 0h
	jne		tru1
	je		khongtru
	tru1:
	sub		bl, 30h
	
	rol		ecx, 8
	sub		cl, 30h
	
	
	add		bl, cl
	add		bl, nho
	
	xor 	eax, eax
	mov		al, bl
	
	push	edx
	xor 	dl, dl
	mov 	bl, 10h
	div		bl
	
	mov 	nho, al
	
	add		ah, 30h
	
	pop		edx
	mov		[edi+edx], ah
	
	dec		dl
	
	cmp 	dl, 0
	jns	 	tinhtong
	
	doneLoop:
	
	push	0
	push	0
	push	0
	push	hFileResult	
	call 	SetFilePointer
	
	push 	NULL
	push	0
	push 	4
	push	offset tmp
	push	hFileResult
	call 	WriteFile
	
	ret
Tong ENDP

start:
	push	NULL
	push 	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ
	push 	GENERIC_READ
	push 	offset fileName1
	call	CreateFile	
	
	mov 	ebx, offset hFile1
	mov 	[ebx], eax
	
	push	0
	push	hFile1
	call 	GetFileSize
	mov 	size1, ax
	
	push	NULL
	push 	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ
	push 	GENERIC_READ
	push 	offset fileName2
	call	CreateFile	
	
	mov 	ebx, offset hFile2
	mov 	[ebx], eax
	
	push	0
	push	hFile2
	call 	GetFileSize
	
	mov		size2, ax
	
	push	NULL
	push 	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	CREATE_ALWAYS
	push	NULL
	push	FILE_SHARE_WRITE
	push 	GENERIC_WRITE
	push 	offset fileName3
	call	CreateFile	
	
	mov 	ebx, offset hFileResult
	mov 	[ebx], eax
	
	xor 	ecx, ecx
	mov		cx, 4h
	
		
	Nhan:
	;kiem tra xem doc het file 1 chua
	kt1:
	mov 	dx, size1
	cmp 	dx, 0h
	ja		kt2
	jmp		done1
	
	
	;kiem tra xem doc het file 2 chua
	kt2:
	mov 	dx, size2
	cmp 	dx, 0h
	ja		donektr
	jmp 	done2
	
	done1:
	mov		ebx, offset buffer1
	xor		eax, eax
	mov		[ebx], eax
	
	mov 	dx, size2
	cmp 	dx, 0h
	ja 		kt2
	jmp		done
	
	
	done2:
	mov		ebx, offset buffer2
	xor		eax, eax
	mov		[ebx], eax
	
	mov 	dx, size1
	cmp 	dx, 0h
	ja		donektr
	
	jmp 	done
	
	donektr:
	
	mov 	dx, size1
	cmp 	dx, 4h
	jb		setSize1
	
	xor 	ebx, ebx
	mov 	bx, size1
	sub 	ebx, 4
	mov		size1, bx
	
	mov		dx, size2
	cmp		dx, 4h
	jb		setSize2
	
	xor 	ebx, ebx
	mov 	bx, size2
	sub 	ebx, 4h
	mov		size2, bx
	jmp		docvatinh
	
	setSize1:
	mov		cx, size1
	mov		cx1, cx
	xor		ax, ax
	mov		size1, ax
	
	mov		dx, size2
	cmp		dx, 4h
	jb		setSize2	
	
	xor 	ebx, ebx
	mov 	bx, size2
	sub 	ebx, 4
	mov		size2, bx
	
	jmp		docvatinh
		
	setSize2:
	mov		cx, size2
	mov 	cx2, cx
	xor		ax, ax
	mov 	size2, ax
	
	jmp 	docvatinh
	

	
	;so 1
	docvatinh:
	
	xor     ecx, ecx
	mov		cx, size1
	
	push	0h
	push	0h
	push	ecx
	push 	hFile1
	call 	SetFilePointer
	

	xor 	ecx, ecx
	mov		cx, cx1
	
	
	push 	NULL
	push	0
	push	ecx
	push	offset buffer1
	push 	hFile1
	call	ReadFile
	
	;so 2
	xor		ecx, ecx
	mov 	cx, size2
	
	push	0
	push	0	
	push	ecx
	push 	hFile2
	call 	SetFilePointer
	
	xor		ecx,ecx
	mov		cx, cx2
	
	push 	NULL
	push	0
	push	ecx
	push	offset buffer2
	push 	hFile2
	call	ReadFile
	
	mov 	ebx, buffer1
	mov		ecx, buffer2
	
	call	Tong
	
	xor 	ecx, ecx
	mov		buffer1, ecx
	mov		buffer2, ecx
	mov		ecx, 4h
	jmp 	Nhan

	
	done:
	
	mov		al, nho
	cmp 	al, 0h
	je		return		
	
	add		al, 30h
	mov 	nho, al
	
	push	0
	push	0
	push	0
	push	hFileResult	
	call 	SetFilePointer
	
	
	push 	NULL
	push	0
	push 	1
	push	offset nho
	push	hFileResult
	call 	WriteFile
	
	return:
	ret
	
end start
