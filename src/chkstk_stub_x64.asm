; chkstk_stub.asm - x64 stub for __chkstk_ms (MinGW compatibility)

.CODE

; External reference to MSVC's __chkstk
EXTERN __chkstk:PROC

; Export ___chkstk_ms (3 underscores - MinGW x64 calling convention)
PUBLIC ___chkstk_ms

___chkstk_ms PROC
    ; Just jump to the real __chkstk provided by MSVC runtime
    jmp __chkstk
___chkstk_ms ENDP

END
