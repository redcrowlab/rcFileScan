# rcFileScan

##########################################################

Red Crow Labs - http://www.redcrowlab.com  

##########################################################

DESCRIPTION: 

File analyzer. Can handle multiple file formats.

There is also a tool called rcSectionMangler which lets you change permisions on a section inside an ELF file. Finally, there is a c program called rcTestBin that can be used to test the scanner.

===========================================================================

INSTALL:

git clone https://github.com/redcrowlab/rcFileScan.git

To compile rcTestBin.c do: 

    gcc -fno-builtin  -fno-stack-protector -O0 -Wl,--build-id -o rcTestBin.ELF rcTestBin.c -ldl -lcrypto

-   -fno-builtin prevents GCC from optimizing bad functions like strcyp
-   -fno-stack-protector prevents GCC from terminating buffer overflows
-   -O0 removes all compiler optimizations for easier debugging
-   -Wl,--build-id enables the build id to the linker which writes to the .notes section of the ELF
-   -ldl enables dynamic loading
-   -lcrypto enables openssl functions for weak crypto tests


If you want to test stack canary detection compile with:

    gcc -fstack-protector-all -fno-builtin  -fcf-protection=full -O0 -Wl,--build-id -o testBin.ELF testBin.c -ldl -lcrypto

## Requirements

Ubuntu, python3, python3-pefile, elfutils, python3-capstone libssl-dev, python3-pyelftools, python3-magic

===========================================================================

USAGE:

rcFileScan.py [-h] [-a] [-s] [-t] [-c] [-i] [-S] [-C] [-l] [-I] [-e] [-E] [-O] [-x] [-X] [-N] [-z] [-b] [-ch] [-lh] [-bi] [-p] [-d] [-cf] [-sc] [-w]
                     file

Process ELF files.

positional arguments:
  file                  Path to the ELF file.

options:
-  -h, --help            show this help message and exit
-  -a, --all             Run all options.
-  -s, --size            Get file size.
-  -t, --type            Get file type.
-  -c, --checksums       Get file checksums (MD5 and SHA256).
-  -i, --count_imports   Count imported symbols.
-  -S, --strings         Extract Strings from Binary.
-  -C, --compile_date    Extract compile date from Binary.
-  -l, --linker_time     Extract linker date from Binary.
-  -I, --imports         Extract imports from Binary.
-  -e, --count_exports   Count Number of Exports.
-  -E, --exports         Extract exports from Binary.
-  -O, --sec_opts        Check security-related compile options.
-  -x, --count_sections  Count the number of sections.
-  -X, --get_sections    Print the details of the sections.
-  -N, --entropy         Calculate the entropy of the file.
-  -z, --syscalls        Attempt to identify and list syscalls.
-  -b, --find_badCalls   Attempt to identify vulnerable API calls.
-  -ch, --count_headers  Count the number of headers.
-  -lh, --list_headers   List the headers.
-  -bi, --bin_info       Get binary information.
-  -p, --permissions     List the permissions on sections.
-  -d, --dynamic_loading Check for dynamic loading functions.
-  -cf, --cfi_check      Check for CFI protections.
-  -sc, --stack_canaries Check for stack canaries.
-  -w, --weak_crypto     Check for weak cryptographic functions.

EXAMPLE:

<pre>
rcFileScan.py -s -t -c -O rcTestBin.ELF
[* FILE SIZE *]: 16.45 KB
[* FILE TYPE *]: relocatable (x86-64)
[* SYSTEM FILE TYPE *]: ('sha1', 'ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2')
[* MD5SUM *]: eb9f5b7da3c5ac80d2efca55e074133a
[* SHA256SUM *]: aafa8e6578f7b90605797f2c8899ec212a87f4aa513dd770f3d233db9126522d
[* SECURITY OPTIONS *]:
RELRO: Enabled
Stack Protection: Disabled
NX: Enabled
ASLR: Disabled
DEP: Enabled
PIE: Disabled
</pre>
===========================================================================



