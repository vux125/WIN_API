.386
.model flat, stdcall
option casemap :none
include C:\masm32\include\windows.inc
include C:\masm32\include\kernel32.inc
include C:\masm32\include\user32.inc
includelib C:\masm32\lib\kernel32.lib
includelib C:\masm32\lib\user32.lib


.data

 pathInput db "C:\Users\My Desktop\Documents\Malware\code\asm\bai1\input.txt",0
 pathOutput db "C:\Users\My Desktop\Documents\Malware\code\asm\bai1\output.txt",0
 titl db "Tong cua mang so nguyen to trong mang la: ", 0
 sum db 32 dup(0)
 data db 100 dup(0)
 read dd 0
 szSum dd 0
 write dd 0
 arrOne db 512 dup(0)
 szOne db 0
 arrTwo db 512 dup(0)
 szTwo db 0
 tmp dd 0
  
 
 .code
 
IntSqrt PROC uses edx n:dword
	finit			; khoi tao FPU
	fild 	n		; n -> ST0
	fsqrt			; ST0 = sqrt(ST0)
	fistp	tmp
	mov		eax, tmp
	mov 	edx, eax
	inc		edx
	imul	edx, edx
	cmp 	edx, n
	ja		done
	inc		eax
done:
	ret
IntSqrt ENDP

IsPrime PROC uses ecx ebx edx, sq:dword, n:dword
	mov 	ecx, 2		
	mov 	eax, n
	cmp 	eax, ecx		;so sanh n voi 2 
	jb		not_prime		; neu nho hon thi khong phai prime
	cmp 	eax, 2
	jne		lap
	mov		eax, 1
	ret
lap:
	mov 	eax, n			
	xor 	edx, edx
	div 	ecx				;eax = eax / ecx, edx = eax % ecx
	cmp		edx, 0			;so sanh so du edx voi 0
	je		not_prime		;neu bang 0 thi khong phai so nguyen to
	
	inc 	ecx				;neu khac 0 thi tang ecx += 1
	cmp		ecx, sq			;so sanh voi ecx vói sq
	jbe		lap				;nho hon hoac bang thi tiep tuc lap
	
	mov 	eax, 1			;het vong lap la so nguyen to tra ve 1
	ret
	
not_prime:
	xor	eax, eax			;khon phai so nguyen to tra ve 0
	ret	
IsPrime ENDP
 
;------------------------------------------------------------------------------------------------------------------------
start:

	;mo file
	push 	0
	push 	FILE_ATTRIBUTE_NORMAL
	push 	3
	push 	NULL
	push 	FILE_SHARE_READ
	push 	GENERIC_READ
	push 	offset pathInput
	call 	CreateFile
	
	
	;doc file
	push 	NULL
	push 	offset read
	push 	512
	push 	offset data
	push 	eax
	call 	ReadFile
	
	push	eax
	call 	CloseHandle
	
	xor 	eax, eax
	xor 	edx, edx
	xor 	ecx, ecx
	xor 	ebx, ebx
	mov 	ebx, offset data
lapsothunhat:
	mov 	dl, [ebx]
	mov 	byte ptr [arrOne+ecx], dl
	mov 	eax, 0
	add 	ebx, 3
	inc 	cl
	cmp 	edx, eax
	jne 	lapsothunhat

	
	sub 	cl, 1
	mov 	byte ptr [szOne], cl
	xor 	eax, eax
	xor 	ecx, ecx
	xor 	ebx, ebx	
	xor		edx, edx
tinhtong:
	movzx 	edx, byte ptr [arrOne+ecx]
	sub 	edx, '0'
	push	edx
	call	IntSqrt
	
	push	edx
	push 	eax
	call 	IsPrime
	
	cmp		eax, 1
	jne		sotieptheo
	add		ebx, edx
	

sotieptheo:	
	inc 	cl
	cmp 	cl, [szOne]
	jl 		tinhtong
	
	xor		eax, eax
	mov 	eax, ebx
	mov 	edi, offset sum
	xor 	ecx, ecx
	
sosangchuoi:
	xor 	edx, edx
	xor 	ebx, ebx
	mov 	ebx, 10
	div 	ebx
	add 	edx, '0'
	push 	edx
	inc 	ecx
	cmp 	eax, 0 
	jnz 	sosangchuoi
	
	mov 	edi, offset sum
	mov 	ebx, offset szSum
	mov 	[ebx], ecx
	

luura:
	pop 	edx
	mov 	[edi], dl
	inc 	edi
	loop	luura
	
	mov		byte ptr [edi], 0 
	mov 	ebx, edi
	
	;in ra file
	push	0
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_ALWAYS
	push	NULL
	push	FILE_SHARE_WRITE
	push	GENERIC_WRITE
	push	offset pathOutput	
	call 	CreateFile
	
	push 	0
	push 	offset write
	push 	offset szSum
	push 	offset sum
	push	eax
	call 	WriteFile
	
	push	eax
	call 	CloseHandle
	
	
 	

end start 
