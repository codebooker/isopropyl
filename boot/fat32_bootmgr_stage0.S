/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Project-authored FAT32 BIOS loader, formatter-BPB merge template. */

.intel_syntax noprefix
.code16
.section .text
.global _start

.equ STAGE_SECTOR, 12
.equ STAGE_SECTORS, 2
.equ STAGE_SEGMENT, 0x1000

_start:
    jmp short entry
    nop

    /* Bytes 3..89 are formatter-owned and remain zero in this template. */
    .org 90

entry:
    cli
    xor ax, ax
    mov ss, ax
    mov sp, 0x7c00
    mov ax, 0x07c0
    mov ds, ax
    sti
    cld
    mov byte ptr [drive], dl

    /* The modern BOOTMGR profile may fill conventional memory through 0x9e000. */
    int 0x12
    cmp ax, 0x278
    jb failure

    mov bx, 0x55aa
    mov ah, 0x41
    int 0x13
    jc failure
    cmp bx, 0xaa55
    jne failure
    test cx, 1
    jz failure

    cmp word ptr [11], 512
    jne failure
    cmp word ptr [14], STAGE_SECTOR + STAGE_SECTORS
    jb failure
    mov eax, dword ptr [28]
    add eax, STAGE_SECTOR
    jc failure
    mov dword ptr [dap_lba], eax
    mov word ptr [dap_segment], STAGE_SEGMENT
    mov si, offset dap
    mov dl, byte ptr [drive]
    mov ah, 0x42
    int 0x13
    jc failure
    mov dl, byte ptr [drive]
    push STAGE_SEGMENT
    xor ax, ax
    push ax
    retf

failure:
    int 0x18
    jmp failure

drive:
    .byte 0
    .balign 2
dap:
    .byte 0x10, 0
    .word STAGE_SECTORS
    .word 0
dap_segment:
    .word 0
dap_lba:
    .long 0, 0

    .org 510
    .word 0xaa55
