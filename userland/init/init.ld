/* Link script for init, the first user-space process.
 *
 * The base address is chosen to be nowhere near the kernel. Stage 1 runs the
 * kernel on an identity mapping of the first 512 GiB, which occupies PML4 entry
 * 0; 0x1000_0000_0000 is PML4 entry 32, so a user address space is the kernel's
 * entry 0 plus one entry of its own with nothing shared but what the syscall
 * path needs.
 *
 * # The `.l` prefixes are not optional
 *
 * init is compiled with `-C code-model=large`, because the small model reaches
 * its own data with 32-bit signed displacements and 16 TiB is far outside that.
 * The large model emits `.ltext`, `.lrodata`, `.ldata`, and `.lbss` rather than
 * the usual names. A script matching only `.text` and `.rodata` therefore
 * matches nothing at all: lld places every section as an orphan, packed end to
 * end, and the read-only segment starts in the middle of the page the
 * executable segment ends in.
 *
 * That is not cosmetic. The kernel maps user segments a page at a time and
 * applies permissions per page, so two segments sharing a page would need the
 * union of their rights. It refuses the image instead
 * (`UserError::UnalignedSegment`), which is why page-aligning each section here
 * is what makes `W^X` expressible for this process at all.
 */

ENTRY(_start)

USER_IMAGE_BASE = 0x100000000000;

SECTIONS
{
    . = USER_IMAGE_BASE;
    __image_start = .;

    .text ALIGN(4096) :
    {
        *(.text .text.*)
        *(.ltext .ltext.*)
    }

    . = ALIGN(4096);
    __text_end = .;

    .rodata ALIGN(4096) :
    {
        *(.rodata .rodata.*)
        *(.lrodata .lrodata.*)
    }

    . = ALIGN(4096);
    __rodata_end = .;

    .data ALIGN(4096) :
    {
        *(.data .data.*)
        *(.ldata .ldata.*)
        *(.got .got.plt)
    }

    .bss ALIGN(4096) :
    {
        *(.bss .bss.*)
        *(.lbss .lbss.*)
        *(COMMON)
        . = ALIGN(4096);
    }

    __image_end = .;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
