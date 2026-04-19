/*
 * Linker script for PIC shellcode compilation.
 * Merges all sections into .text so that objcopy -O binary -j .text
 * extracts a complete flat binary with no dangling RIP-relative
 * references to stripped .rdata/.data/.bss sections.
 *
 * Without this, GCC -Os optimizes local array initializers by storing
 * constant values in .rdata and generating memcpy-style init sequences.
 * After .text-only extraction those RIP-relative loads point to
 * unmapped memory -> AccessViolation.
 */
SECTIONS {
    .text : {
        *(.text)
        *(.text.*)
        *(.rdata)
        *(.rdata.*)
        *(.data)
        *(.data.*)
        *(.bss)
        *(.bss.*)
    }
}
