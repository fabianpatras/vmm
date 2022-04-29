[BITS 64]

MOV RAX, CR0
AND AX, 1

CMP AX,0
JE real

MOV RAX, 0xffff
JMP ender

real:
MOV RAX, 0xaaaa

ender:
HLT
