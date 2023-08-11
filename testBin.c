#define _GNU_SOURCE
#include <stdio.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <string.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <time.h>

/////////////////////////////////////////////////////////////////////////
// RedCrow Lab - http://www.redcrowlab.com 
// rcTestBIN.ELF
// This is a test binary for testing rcFileScan. It has many of the features rcFileScan scans for.

// To compile do: gcc -fno-builtin  -fno-stack-protector -O0 -Wl,--build-id -o testBin.ELF testBin.c -ldl -lcrypto
// -fno-builtin prevents GCC from optimizing bad functions like strcyp
// -fno-stack-protector prevents GCC from terminating buffer overflows
// -O0 removes all compiler optimizations for easier debugging
// -Wl,--build-id enables the build id to the linker which writes to the .notes section of the ELF
// -ldl enables dynamic loading
// -lcrypto enables openssl functions for weak crypto tests
// If you want to test stack canary detection compile with:
// gcc -fstack-protector-all -fno-builtin  -fcf-protection=full -O0 -Wl,--build-id -o testBin.ELF testBin.c -ldl -lcrypto

const char *compile_date = __DATE__;
const char *compile_time = __TIME__;

////////////////////////////////////////////////////////////////////////
// Test Function so the tools have functions to enumerate, graph, etc.
int testFunction() {
        printf("Inside Test Function\n");
        return 0;
}

////////////////////////////////////////////////////////////////////////
// Test function that takes in a var for other types of enumeration.
int testFunction2(const char *testVar) {
        printf("Test Var: %s \n", testVar);
        return 0;
}

// Create Custom section. Set read and execute permissions with rcSectionMangler.py
__attribute__((section(".custom_section"))) void customSection() {
        printf("Inside custom section\n");
}
__asm__(".section .custom_section,\"ax\",@progbits\n");

////////////////////////////////////////////////////////////////////////
// Implementation of a weak cryptographic function
void weakCryptoFunctionMD5() {
	unsigned char digest[MD5_DIGEST_LENGTH];
	char string[] = "WeakCrypto";

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, string, strlen(string));
	MD5_Final(digest, &ctx);

	printf("MD5 digest of %s: ", string);
	for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
}

////////////////////////////////////////////////////////////////////////
// Implementation of a weak random function
void weakRandomFunction() {
	srand(time(NULL));
	int weakRandomNumber = rand(); // Weak random number

	printf("Weak random number: %d\n", weakRandomNumber);
}

////////////////////////////////////////////////////////////////////////
// Implementation of another weak crypto function
void weakCryptoFunctionROT13() {
	char string[] = "WeakCrypto";
	int length = strlen(string);

	printf("Original string: %s\n", string);

	// Apply ROT13
	for(int i = 0; i < length; i++) {
		if (string[i] >= 'a' && string[i] <= 'z') {
			string[i] = (string[i] - 'a' + 13) % 26 + 'a';
		} else if (string[i] >= 'A' && string[i] <= 'Z') {
			string[i] = (string[i] - 'A' + 13) % 26 + 'A';
		}
	}

	printf("ROT13 encoded string: %s\n", string);
}

////////////////////////////////////////////////////////////////////////
// MAIN
int main() {
        printf("In main running the test\n");

        // Add some compiled date strings, need to figure out where in the ELF header to put this.
        printf("Compiled on: %s at %s\n", compile_date, compile_time);

        const char *myVar = "SecretPassword";
        const char *password = "hardcoded_password"; // Hardcoded password
        const char *apikey = "a1b2c33d4e5f6g7h8i9jakblc"; // Hardcoded API key

        // Call test functions
        testFunction();
        testFunction2(myVar);

        // SYSCALL tests need work
        //const char *message = "SYSCALL TEST!\n";
        //syscall(SYS_write, 1, message, 16);

        // Dynamic loading example
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if (handle) {
                typedef void (*printf_t)(const char *, ...);
                printf_t dynamicPrintf = (printf_t)dlsym(handle, "printf");
                if (dynamicPrintf) {
                        dynamicPrintf("Dynamically loaded printf\n");
                }
                dlclose(handle);
        }

        // Vulnerable strcpy call
        char buffer[10];
        strcpy(buffer, "This string is too long for the buffer");

        // Call weak crypto and rand functions for test
        weakCryptoFunctionMD5();
        weakCryptoFunctionROT13();
        weakRandomFunction();

        // Call custom section
        customSection();

        return 0;
}
