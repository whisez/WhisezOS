/* Link script for the WhisezOS microkernel.
 *
 * The load address is fixed and low. Two reasons:
 *
 *   - Stage 1 runs on the identity mapping UEFI leaves behind, so virtual and
 *     physical addresses are the same and the loader can place the image where
 *     the ELF asks for it. A higher-half link needs page tables built before the
 *     first instruction runs, which is loader work that does not exist yet.
 *   - 32 MiB sits inside the large free block OVMF leaves above its own
 *     allocations. 16 MiB does not: OVMF occupies roughly 8..23 MiB, and the
 *     loader's `AllocateType::Address` fails outright there.
 *
 * That is a real limitation of a fixed link address, not a solved problem —
 * firmware that lays memory out differently will fail the same way. The loader
 * prints the free conventional ranges when the allocation fails, so the fix is
 * to relink here rather than to guess.
 *
 * The section symbols are not decoration: arch/memory.rs maps the image a page
 * at a time using them, so text ends up executable and read-only while data and
 * bss end up writable and non-executable. Removing a symbol here breaks W^X for
 * the kernel's own image.
 */

ENTRY(_start)

KERNEL_PHYS_BASE = 0x2000000;

SECTIONS
{
    . = KERNEL_PHYS_BASE;
    __kernel_start = .;

    .text : ALIGN(4096)
    {
        *(.text.boot)
        *(.text .text.*)
    }

    /* Page granularity throughout: the mapper works in 4 KiB pages, so a
     * section boundary that falls mid-page would force one page to be both
     * writable and executable, which map_page refuses outright. */
    . = ALIGN(4096);
    __text_end = .;

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
    __rodata_end = .;

    .data : ALIGN(4096)
    {
        *(.data .data.*)
        *(.got .got.plt)
    }

    .bss : ALIGN(4096)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4096);
        __bss_end = .;
    }

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
