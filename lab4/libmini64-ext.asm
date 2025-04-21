
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

%include 'libmini.inc'
extern	errno

	section .data
seed:			db 0

	section .text

    gensys 201, time

; ======================================
	global time:function
time:
	call	sys_time
	cmp	rax, 0
	jge	time_success	; no error :)
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
	mov QWORD [seed wrt rip], rdi
	ret

; ======================================
	global grand:function
grand:
	mov rax, QWORD [seed wrt rip]
	ret

; ======================================
	global rand:function
rand:
	; seed = 6364136223846793005ULL*seed + 1
	mov rax, QWORD [seed wrt rip]
	mov rdx, rand_constant
    imul rax, rdx
	add rax, 1
	mov QWORD [seed wrt rip], rax
	; seed>>33
    mov rax, QWORD [seed wrt rip]
	shr rax, 33
	ret

; ======================================
	global sigemptyset:function
sigemptyset:
    ; rdi
	; cmp	rdi, 0
	; jge	sigemptyset_error	; null pointer check
    mov QWORD [rdi], 0
sigemptyset_success:
	; mov	rdi, [rel errno wrt ..gotpcrel]
	; mov	QWORD [rdi], 0	; errno = 0
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
	; cmp	rdi, 0
	; jge	sigfillset_error	; null pointer check
    mov QWORD [rdi], 0xffffffffffffffff
sigfillset_success:
	; mov	rdi, [rel errno wrt ..gotpcrel]
	; mov	QWORD [rdi], 0	; errno = 0
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
    mov rdx, QWORD [rdi]
    or rdx, r11
    mov QWORD [rdi], rdx
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
    mov rdx, QWORD [rdi]
    and rdx, r11
    mov QWORD [rdi], rdx
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
    mov rdx, QWORD [rdi]
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
sigprocmask_success:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], 0	; errno = 0
    mov	rax, 0
    jmp	sigprocmask_quit
sigprocmask_error:
	mov	rdi, [rel errno wrt ..gotpcrel]
	mov	QWORD [rdi], -22	; errno = -EINVAL
	mov	rax, -1
sigprocmask_quit:
	ret
