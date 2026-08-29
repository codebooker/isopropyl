/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Project-authored FAT32 root-file loader.
 *
 * Stage 0 loads these two sectors at 1000:0000.  This code loads the exact
 * short-name BOOTMGR file at 2000:0000, requires the pinned modern Windows 11
 * entry stub, then transfers to 2000:0000.  The layout follows Rufus's distinct
 * FAT32 PE profile but still requires an authentic Windows/SeaBIOS certificate
 * before ISOpropyl may claim general Microsoft BOOTMGR compatibility.
 */

.intel_syntax noprefix
.code16
.section .text
.global _start

.equ ORIGINAL_BPB_SEGMENT, 0x07c0
.equ BPB_SEGMENT, 0x1400
.equ SCRATCH_SEGMENT, 0x1600
.equ STACK_SEGMENT, 0x1800
.equ LOAD_SEGMENT, 0x2000
.equ LOAD_LIMIT_SEGMENT, 0x9e00

_start:
    cli
    mov ax, cs
    mov ds, ax
    mov ax, STACK_SEGMENT
    mov ss, ax
    mov sp, 0x7000
    /* Preserve the formatter BPB in private memory below the modern payload. */
    mov ax, ORIGINAL_BPB_SEGMENT
    mov ds, ax
    mov ax, BPB_SEGMENT
    mov es, ax
    xor si, si
    xor di, di
    mov cx, 256
    cld
    rep movsw
    mov ax, cs
    mov ds, ax
    mov ax, BPB_SEGMENT
    mov fs, ax
    sti
    cld
    mov byte ptr [drive], dl

    cmp word ptr fs:[11], 512
    jne failure
    mov al, byte ptr fs:[13]
    test al, al
    jz failure
    mov ah, al
    dec ah
    test al, ah
    jnz failure
    test al, 0x80
    jnz failure
    mov byte ptr [cluster_sectors], al
    cmp byte ptr fs:[16], 2
    jne failure
    cmp word ptr fs:[17], 0
    jne failure
    cmp word ptr fs:[19], 0
    jne failure
    cmp word ptr fs:[22], 0
    jne failure
    cmp word ptr fs:[42], 0
    jne failure

    movzx ebx, word ptr fs:[14]
    cmp ebx, 14
    jb failure
    mov edx, dword ptr fs:[28]
    mov eax, dword ptr fs:[32]
    test eax, eax
    jz failure
    add eax, edx
    jc failure
    mov dword ptr [volume_end], eax
    add edx, ebx
    jc failure
    mov dword ptr [fat_start], edx
    mov eax, dword ptr fs:[36]
    test eax, eax
    jz failure
    cmp eax, 0x01ffffff
    ja failure
    mov ecx, eax
    add eax, eax
    jc failure
    add eax, edx
    jc failure
    mov dword ptr [data_start], eax
    cmp eax, dword ptr [volume_end]
    jae failure
    mov edx, dword ptr [volume_end]
    sub edx, eax
    movzx ebx, byte ptr [cluster_sectors]
    mov eax, edx
    xor edx, edx
    div ebx
    cmp eax, 65525
    jb failure
    add eax, 2
    jc failure
    cmp eax, 0x0ffffff0
    ja failure
    mov dword ptr [cluster_end], eax
    shl ecx, 7
    cmp eax, ecx
    ja failure

    mov eax, dword ptr fs:[44]
    mov ebp, dword ptr [cluster_end]
    sub ebp, 2

directory_cluster:
    test ebp, ebp
    jz failure
    dec ebp
    mov dword ptr [current_cluster], eax
    call cluster_lba
    mov byte ptr [sectors_left], cl

directory_sector:
    mov dx, SCRATCH_SEGMENT
    mov es, dx
    xor bx, bx
    call read_sector
    inc eax
    xor di, di
    mov cx, 16

directory_entry:
    cmp byte ptr es:[di], 0
    je failure
    cmp byte ptr es:[di], 0xe5
    je next_entry
    mov bl, byte ptr es:[di + 11]
    cmp bl, 0x0f
    je next_entry
    test bl, 0x18
    jnz next_entry
    push cx
    push di
    mov si, offset bootmgr_name
    mov cx, 11
    repe cmpsb
    pop di
    pop cx
    je found

next_entry:
    add di, 32
    loop directory_entry
    dec byte ptr [sectors_left]
    jnz directory_sector
    mov eax, dword ptr [current_cluster]
    call next_cluster
    cmp eax, 0x0ffffff8
    jb directory_cluster
    jmp failure

found:
    movzx eax, word ptr es:[di + 20]
    shl eax, 16
    mov ax, word ptr es:[di + 26]
    mov edx, dword ptr es:[di + 28]
    cmp edx, 0x1d9
    jb failure
    cmp edx, 0x7e000
    ja failure
    mov dword ptr [file_left], edx
    mov ebp, dword ptr [cluster_end]
    sub ebp, 2
    mov dx, LOAD_SEGMENT
    mov es, dx
    xor bx, bx

file_cluster:
    test ebp, ebp
    jz failure
    dec ebp
    mov dword ptr [current_cluster], eax
    call cluster_lba
    mov byte ptr [sectors_left], cl

file_sector:
    call read_sector
    inc eax
    cmp dword ptr [file_left], 512
    jbe launch
    sub dword ptr [file_left], 512
    add bx, 512
    jnc file_buffer_ok
    mov dx, es
    add dx, 0x1000
    cmp dx, LOAD_LIMIT_SEGMENT
    jae failure
    mov es, dx
file_buffer_ok:
    dec byte ptr [sectors_left]
    jnz file_sector
    mov eax, dword ptr [current_cluster]
    call next_cluster
    cmp eax, 0x0ffffff8
    jb file_cluster
    jmp failure

launch:
    mov dx, LOAD_SEGMENT
    mov es, dx
    cmp dword ptr es:[0], 0xeb01d5e9
    jne failure
    cmp word ptr es:[4], 0x9004
    jne failure
    xor dx, dx
    mov dl, byte ptr [drive]
    xor ax, ax
    mov ds, ax
    mov es, ax
    push LOAD_SEGMENT
    push 0
    retf

/* EAX=cluster -> EAX=absolute first sector, CL=sectors per cluster. */
cluster_lba:
    cmp eax, 2
    jb failure
    cmp eax, dword ptr [cluster_end]
    jae failure
    sub eax, 2
    movzx ecx, byte ptr [cluster_sectors]
    mul ecx
    test edx, edx
    jnz failure
    add eax, dword ptr [data_start]
    jc failure
    cmp eax, dword ptr [volume_end]
    jae failure
    ret

/* EAX=cluster -> EAX=masked FAT32 successor.  ES is preserved. */
next_cluster:
    push es
    push bx
    shl eax, 2
    mov si, ax
    and si, 511
    shr eax, 9
    add eax, dword ptr [fat_start]
    jc failure_pop_es
    cmp eax, dword ptr [data_start]
    jae failure_pop_es
    mov bx, SCRATCH_SEGMENT
    mov es, bx
    xor bx, bx
    call read_sector
    mov eax, dword ptr es:[si]
    and eax, 0x0fffffff
    pop bx
    pop es
    ret

failure_pop_es:
    pop bx
    pop es
failure:
    int 0x18
    jmp failure

/* Read one absolute EDD sector from EAX into ES:BX; preserve EAX/BX. */
read_sector:
    mov dword ptr [saved_eax], eax
    mov dword ptr [saved_ebx], ebx
    mov dword ptr [saved_ecx], ecx
    mov dword ptr [saved_edx], edx
    mov dword ptr [saved_esi], esi
    mov dword ptr [saved_edi], edi
    mov dword ptr [saved_ebp], ebp
    mov word ptr [saved_es], es
    mov word ptr [dap_buffer], bx
    mov word ptr [dap_buffer + 2], es
    mov dword ptr [dap_lba], eax
    mov si, offset dap
    mov dl, byte ptr [drive]
    mov ah, 0x42
    /* Some BIOS paths use the caller's stack scratch below SP.  Keep the
       near-return word away from that scratch while registers live in memory. */
    push eax
    push eax
    int 0x13
    jc failure_read_guard
    add sp, 8
    push cs
    pop ds
    mov ax, word ptr [saved_es]
    mov es, ax
    mov ebx, dword ptr [saved_ebx]
    mov ecx, dword ptr [saved_ecx]
    mov edx, dword ptr [saved_edx]
    mov esi, dword ptr [saved_esi]
    mov edi, dword ptr [saved_edi]
    mov ebp, dword ptr [saved_ebp]
    mov eax, dword ptr [saved_eax]
    ret
failure_read_guard:
    add sp, 8
failure_read:
    push cs
    pop ds
    mov ax, word ptr [saved_es]
    mov es, ax
    mov ebx, dword ptr [saved_ebx]
    mov ecx, dword ptr [saved_ecx]
    mov edx, dword ptr [saved_edx]
    mov esi, dword ptr [saved_esi]
    mov edi, dword ptr [saved_edi]
    mov ebp, dword ptr [saved_ebp]
    mov eax, dword ptr [saved_eax]
    jmp failure

bootmgr_name:
    .ascii "BOOTMGR    "
drive:
    .byte 0
cluster_sectors:
    .byte 0
sectors_left:
    .byte 0
    .balign 2
fat_start:
    .long 0
data_start:
    .long 0
volume_end:
    .long 0
cluster_end:
    .long 0
current_cluster:
    .long 0
file_left:
    .long 0
dap:
    .byte 0x10, 0
    .word 1
dap_buffer:
    .word 0, 0
dap_lba:
    .long 0, 0
saved_eax:
    .long 0
saved_ebx:
    .long 0
saved_ecx:
    .long 0
saved_edx:
    .long 0
saved_esi:
    .long 0
saved_edi:
    .long 0
saved_ebp:
    .long 0
saved_es:
    .word 0

    .org 1024
