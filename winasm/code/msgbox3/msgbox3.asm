; msgbox.asm
	
.386
.model flat, stdcall
option casemap:none

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

.data
	szWndTitle	db	"Wnd Title",0
	szWndText	db	"Wnd Text",0

.code

start:

	push	0
	call	ExitProcess

end	start