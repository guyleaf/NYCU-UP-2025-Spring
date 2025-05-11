%macro gensys 2
	global sys_%2:function
sys_%2:
	push	r10
	mov	r10, rcx
	mov	rax, %1
	syscall
	pop	r10
	ret
%endmacro

; 6364136223846793005ULL
%define rand_constant	0x5851f42d4c957f2d

; RDI, RSI, RDX, RCX, R8, R9

; %include 'libmini.inc'
extern	errno

	section .data
seed:	dq				0

	section .text

	gensys 14, rt_sigprocmask
    gensys 201, time

; ======================================
	global time:function
time:
	call sys_time
	cmp	rax, 0
	jge	time_success
time_error:
	neg	rax
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	[rdi], rax	; errno = -rax
	mov	rax, -1
	jmp	time_quit
time_success:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], 0	; errno = 0
time_quit:
	ret

; ======================================
	global srand:function
srand:
	sub rdi, 1
	mov [seed wrt rip], rdi
	ret

; ======================================
	global grand:function
grand:
	mov rax, [seed wrt rip]
	ret

; ======================================
	global rand:function
rand:
	; seed = 6364136223846793005ULL*seed + 1
	mov rax, [seed wrt rip]
	mov rdx, rand_constant
    imul rax, rdx
	add rax, 1
	mov [seed wrt rip], rax
	; seed>>33
    mov rax, [seed wrt rip]
	shr rax, 33
	ret

; ======================================
	global sigemptyset:function
sigemptyset:
    ; rdi
    mov QWORD [rdi], 0
sigemptyset_success:
    mov	rax, 0
    jmp	sigemptyset_quit
sigemptyset_error:
	mov	rax, -1
sigemptyset_quit:
	ret

; ======================================
	global sigfillset:function
sigfillset:
    ; rdi
    mov QWORD [rdi], 0xffffffff ; in yasm, only support imm32 to r/64 in x86-64. so, it will be sign-extended to 64 bits
sigfillset_success:
    mov	rax, 0
    jmp	sigfillset_quit
sigfillset_error:
	mov	rax, -1
sigfillset_quit:
	ret

; ======================================
	global sigaddset:function
sigaddset:
    ; rdi, rsi
    cmp rsi, 1 ; if rsi < 1
    jl sigaddset_error
    cmp rsi, 32 ; if rsi > 32
    jg sigaddset_error
    ; 1UL << (n - 1)
    mov r11, 1
    sub rsi, 1
	mov rcx, rsi
    shl r11, cl
    ; mask |= 1UL << (n - 1)
    mov rdx, [rdi]
    or rdx, r11
    mov [rdi], rdx
sigaddset_success:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], 0	; errno = 0
    mov	rax, 0
    jmp	sigaddset_quit
sigaddset_error:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], -22	; errno = -EINVAL
	mov	rax, -1
sigaddset_quit:
	ret

; ======================================
	global sigdelset:function
sigdelset:
    ; rdi, rsi
    cmp rsi, 1 ; if rsi < 1
    jl sigdelset_error
    cmp rsi, 32 ; if rsi > 32
    jg sigdelset_error
    ; ~(1UL << (n - 1))
    mov r11, 1
    sub rsi, 1
	mov rcx, rsi
    shl r11, cl
    not r11
    ; mask &= ~(1UL << (n - 1))
    mov rdx, [rdi]
    and rdx, r11
    mov [rdi], rdx
sigdelset_success:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], 0	; errno = 0
    mov	rax, 0
    jmp	sigdelset_quit
sigdelset_error:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], -22	; errno = -EINVAL
	mov	rax, -1
sigdelset_quit:
	ret

; ======================================
	global sigismember:function
sigismember:
    ; rdi, rsi
    cmp rsi, 1 ; if rsi < 1
    jl sigismember_error
    cmp rsi, 32 ; if rsi > 32
    jg sigismember_error
    ; 1UL << (n - 1)
    mov r11, 1
    sub rsi, 1
	mov rcx, rsi
    shl r11, cl
    ; mask &= (1UL << (n - 1))
    mov rdx, [rdi]
    and rdx, r11
    cmp rdx, 0
    je sigismember_notexist
sigismember_exist:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], 0	; errno = 0
    mov	rax, 1
    jmp	sigismember_quit
sigismember_notexist:
    mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], 0	; errno = 0
    mov	rax, 0
    jmp	sigismember_quit
sigismember_error:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], -22	; errno = -EINVAL
	mov	rax, -1
sigismember_quit:
	ret

; ======================================
	global sigprocmask:function
sigprocmask:
    ; rdi: how, rsi: const sigset_t *newset, rdx: sigset_t *oldset
	; rcx: sizeof(sigset_t)
	mov rcx, 0x8
	call sys_rt_sigprocmask
	cmp rax, 0
	jge sigprocmask_success
sigprocmask_error:
	neg	rax
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov [rdi], rax	; errno = -rax
	mov	rax, -1
	jmp	sigprocmask_quit
sigprocmask_success:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], 0	; errno = 0
	mov rax, 0
sigprocmask_quit:
	ret

; ======================================
	global setjmp:function
setjmp:
	; rdi: memory address of jmp_buf jb
	push rdi
	push rsi
	push rdx
	push rcx

	; get current signal mask
	sub rsp, 8
	mov rdi, 0 ; SIG_BLOCK
	mov rsi, 0 ; NULL ptr
	lea rdx, [rsp] ; allocate memory space for oldset
	mov rcx, 0x8

	call sigprocmask
	pop r11 ; move signal mask to %r11

	pop rcx
	pop rdx
	pop rsi
	pop rdi

	mov r10, [rsp] ; move return address to %r10
	; save callee-saved registers
	mov [rdi], rbx
	mov 8[rdi], rbp
	mov 16[rdi], rsp
	mov 24[rdi], r12
	mov 32[rdi], r13
	mov 40[rdi], r14
	mov 48[rdi], r15
	mov 56[rdi], r10 ; return address
	mov 64[rdi], r11 ; signal mask
	mov rax, 0
	ret

; ======================================
	global longjmp:function
longjmp:
	; rdi: jmp_buf jb, rsi: int val
	push rdi
	push rsi
	push rdx
	push rcx
	push QWORD 64[rdi] ; push signal mask

	; restore signal mask
	mov rdi, 2 ; SIG_SETMASK
	lea rsi, [rsp] ; mask address
	mov rdx, 0 ; NULL ptr
	mov rcx, 0x8

	call sigprocmask

	add rsp, 8
	pop rcx
	pop rdx
	pop rsi
	pop rdi

	; NOTE: after this line, the state is not in longjmp
	; restore callee-saved registers
	mov rbx, [rdi]
	mov rbp, 8[rdi]
	mov rsp, 16[rdi]
	mov r12, 24[rdi]
	mov r13, 32[rdi]
	mov r14, 40[rdi]
	mov r15, 48[rdi]

	; replace return address
	mov r11, 56[rdi]
	mov [rsp], r11

	mov rax, rsi ; set return value
	ret
