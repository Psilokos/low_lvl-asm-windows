MSGBOX = msgbox2

all: $(MSGBOX) injector

$(MSGBOX): $(MSGBOX).obj
	\masm32\bin\link /SUBSYSTEM:WINDOWS $(MSGBOX).obj

$(MSGBOX).obj:
	xcopy /y E:\winasm\code\$(MSGBOX)\$(MSGBOX).masm C:\Users\psilokos\Documents\low_lvl-asm-windows\$(MSGBOX)
	\masm32\bin\ml /c /coff /nologo $(MSGBOX).masm

injector: injector.obj
	\GoLink\GoLink.exe /entry _start injector.obj kernel32.dll

injector.obj:
	xcopy /y E:\winasm\code\$(MSGBOX)\injector.asm C:\Users\psilokos\Documents\low_lvl-asm-windows\$(MSGBOX)
	\nasm\nasm.exe -f win64 -i nasmx/inc/ injector.asm -o injector.obj

clean:
	del injector.obj $(MSGBOX).obj

fclean: clean
	del injector.exe $(MSGBOX).exe

re: fclean all

.PHONY: all clean fclean re
