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
	
	outputreal db "outputreal.txt", 0
	hOutputReal dd 0
	
	nho db 0
	tmp db 0
	size1 dd 0
	size2 dd 0
	sizef dd 0
	
	sizereal dd 0
	
	byte1 db 0
	byte2 db 0
	
	ok1 db 1
	ok2 db 1
	
	readbyte db 0
.code
start:
	;mo file input.txt
	push	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	NULL
	push	FILE_SHARE_READ
	push	GENERIC_READ
	push	offset input
	call	CreateFile
	
	mov		hInput, eax
	
	;mo file output.txt
	push	NULL
	push	FILE_ATTRIBUTE_NORMAL
	push	CREATE_ALWAYS
	push	NULL
	push	FILE_SHARE_READ or FILE_SHARE_WRITE
	push	GENERIC_READ or GENERIC_WRITE
	push	offset output
	call	CreateFile
			
	mov		hOutput, eax
	
	;kiem tra kic thuoc so 1
	;lap cho toi khi gap ky tu \n
	
	xor		ecx, ecx
	
	kichthuocsomot:
		push	ecx
		push	NULL
		push	NULL
		push	1
		push	offset tmp
		push	hInput
		call 	ReadFile
		
		pop		ecx
		inc		ecx
		
		mov		al, tmp
		cmp 	al, 13
		jne 	kichthuocsomot
		
	sub		ecx, 2
	mov		size1, ecx
	
	push	NULL
	push	hInput
	call 	GetFileSize
	
	sub 	eax, 1
	mov		sizef, eax
	mov		eax, size1
	
	add		eax, 3
	mov		size2, eax
	
	push 	0
	push	0
	push	0
	push	hInput
	call 	SetFilePointer
	
	;lap con tung byte tu cuoi ve dau
	
	lapdoc:
		xor		edx, edx
		mov		edx, size1
		cmp		edx, 0
		jns		docsomot
		jmp		setsomot
		
		ktr2:
		xor		edx, edx
		mov		edx, sizef
		cmp		edx, size2
		jae		docsohai
		jmp		setsohai
		
		;di chuyen con tro ve tu cuoi so 1
		docsomot:
		push	0
		push	0
		push	size1
		push	hInput
		call 	SetFilePointer
		
		;doc mot byte
		push	NULL
		push	NULL
		push	1
		push	offset byte1
		push	hInput
		call 	ReadFile
		jmp		ktr2
		
		setsomot:
		xor		eax, eax
		mov		ok1, al
		mov		ah, ok2
		cmp		ah, 0
		je		done
		mov		byte1, 30h
		jmp		ktr2
		
		
		
		;di chuyen con tro ve tu cuoi so 2
		docsohai:
		push	0
		push	0
		push	sizef
		push	hInput
		call 	SetFilePointer
		
		;doc mot byte
		push	NULL
		push	NULL
		push	1
		push	offset byte2
		push	hInput
		call 	ReadFile
		jmp		tinhtoan
		
		setsohai:
		xor		eax, eax
		mov		ok2, al
		mov		ah, ok1
		cmp		ah, 0
		je		done
		mov		byte2, 30h
		
		tinhtoan:
		xor		eax, eax
		
		mov		al, byte1
		sub		al, 30h

		mov		bl, byte2
		sub		bl, 30h
		
		add		al, bl
		add		al, nho
		
		xor 	ecx, ecx
		mov		nho, cl
		mov		cl, 10
		
		div		cl
		mov		nho, al
		add		ah, 30h
		mov		tmp, ah
		
		push 	NULL
		push	NULL
		push 	1
		push	offset tmp
		push	hOutput
		call	WriteFile
		
		xor		edx, edx
		mov		edx, size1
		dec		edx
		mov		size1, edx
		
		xor		edx, edx
		mov		edx, sizef
		dec		edx
		mov		sizef, edx
		
		
		jmp lapdoc
		
	done: 
		xor		eax, eax
		mov		al, nho
		cmp 	al, 0
		jne		wri
		je		return
		
	wri:
		mov		tmp, 31h
		
		push 	NULL
		push	NULL
		push 	1
		push	offset tmp
		push	hOutput
		call	WriteFile
	return:
		push	NULL
		push	hOutput
		call	GetFileSize
		
		xor		ecx, ecx
		mov		sizereal, eax
		
		push	2
		push	0
		push	0
		push	hOutput
		call	SetFilePointer
		
		push	NULL
		push	FILE_ATTRIBUTE_NORMAL
		push	CREATE_ALWAYS
		push	NULL
		push	FILE_SHARE_WRITE
		push	GENERIC_WRITE
		push	offset outputreal
		call	CreateFile
			
		mov		hOutputReal, eax
		
		ghinguoc:
			mov		ecx, sizereal
			dec		ecx
			mov		sizereal, ecx
			mov		ebx, ecx
		
			push	0
			push	0
			push	ebx
			push	hOutput
			call	SetFilePointer
			
			push	NULL
			push	NULL
			push	1
			push	offset tmp
			push	hOutput
			call 	ReadFile
		
			
			push	NULL
			push	NULL
			push	1
			push	offset tmp
			push	hOutputReal
			call 	WriteFile
			
			mov		ecx, sizereal
			cmp 	ecx, 0h
			jne		ghinguoc
		
		push 	hInput
		call 	CloseHandle
		
		push 	hOutput
		call 	CloseHandle
		
		push	offset output
		call 	DeleteFile
		
		push 	hOutputReal
		call 	CloseHandle
		ret
end start
