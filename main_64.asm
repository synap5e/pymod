global on_hook_asm
global spin_lock
global spin_unlock

;section .data
;align 16
;fpu: times 108 db 0
;locked: dd      0    ; Simple spinlock. 1 = locked, 0 = unlocked.

section .text



;section .text

; TODO a better form of synchronization
spin_lock:
	mov 	rax, 1 			; Set the EAX register to 1.

	xchg    rax, [-1]		; Atomically swap the EAX register with
							;  the lock variable.
							; This will always store 1 to the lock, leaving
							;  previous value in the EAX register.

	test 	rax, rax 		; Test EAX with itself. Among other things, this will
							;  set the processor's Zero Flag if EAX is 0.
							; If EAX is 0, then the lock was unlocked and
							;  we just locked it.
							; Otherwise, EAX is 1 and we didn't acquire the lock.

	jnz		spin_lock 		; Jump back to the MOV instruction if the Zero Flag is
							;  not set; the lock was previously locked, and so
							; we need to spin until it becomes unlocked.

	ret						; The lock has been acquired, return to the calling
							;  function.

spin_unlock:
	mov 	rax, 0 			; Set the EAX register to 0.

	xchg    rax, [-1]		; Atomically swap the EAX register with
							;  the lock variable.

	ret						; The lock has been released.

on_hook_asm:
	;int 3

	push rsp
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	pushfq

	call spin_lock
	fsave [-1]

	mov rdi, rsp
	call [-1] ; call on_hook_c

	frstor [-1]
	call spin_unlock

	popfq
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	pop rsp

	jmp [-1]
