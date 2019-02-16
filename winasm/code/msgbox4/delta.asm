; delta.asm
	
.386
.model flat, stdcall
option casemap:none

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

.data
	dd	0

.code

start:

	push	delta
delta:
	pop	ebp
	sub	ebp,offset delta

	lea	eax,[ebp + szWndTitle]
	lea	ebx,[ebp + szWndText]
		
	push	MB_OK
	push	eax
	push	ebx
	push	0
	call	MessageBoxA

	push	0
	call	ExitProcess

	szWndTitle	db	"Wnd Title",0
	szWndText	db	"Wnd Text",0

end	start