global on_hook_asm
global spin_lock
global spin_unlock
global _on_hook_asm
global _spin_lock
global _spin_unlock

;section .data
;align 16
;fpu: times 108 db 0
;locked: dd      0    ; Simple spinlock. 1 = locked, 0 = unlocked.

section .text



;section .text

; TODO a better form of synchronization
spin_lock:
_spin_lock:
	mov 	eax, 1 			; Set the EAX register to 1.

	xchg    eax, [-1]		; Atomically swap the EAX register with
							;  the lock variable.
							; This will always store 1 to the lock, leaving
							;  previous value in the EAX register.

	test 	eax, eax 		; Test EAX with itself. Among other things, this will
							;  set the processor's Zero Flag if EAX is 0.
							; If EAX is 0, then the lock was unlocked and
							;  we just locked it.
							; Otherwise, EAX is 1 and we didn't acquire the lock.

	jnz		_spin_lock 		; Jump back to the MOV instruction if the Zero Flag is
							;  not set; the lock was previously locked, and so
							; we need to spin until it becomes unlocked.

	ret						; The lock has been acquired, return to the calling
							;  function.

spin_unlock:
_spin_unlock:
	mov 	eax, 0 			; Set the EAX register to 0.

	xchg    eax, [-1]		; Atomically swap the EAX register with
							;  the lock variable.

	ret						; The lock has been released.

on_hook_asm:
_on_hook_asm:
	;int 3

	push esp
	push eax
	push ebx
	push ecx
	push edx
	push esi
	push edi
	push ebp
	pushfd

	call _spin_lock
	fsave [-1]

	push esp
	call [-1] ; call on_hook_c
	add esp, 4

	frstor [-1]
	call _spin_unlock

	popfd
	pop ebp
	pop edi
	pop esi
	pop edx
	pop ecx
	pop ebx
	pop eax
	pop esp

;   the python code now fixed $sp
;	mov [esp], eax 	; remove the return address
;	pop eax 		; this is add esp,4 without changing eflags
	jmp [-1]
