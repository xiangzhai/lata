/*
 * Copyright (c) 2026, Loongson Technology. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * LATA does not model pointer authentication.  XPACI/XPACD must strip
 * nothing, and the PAC/AUT forms must behave as no-ops, so that plain arm64
 * Darling libraries (libdyld, libsystem_kernel, ...) run on non-PAC hosts.
 */

#include <stdio.h>

static unsigned long xpaci(unsigned long in)
{
    unsigned long out;
    asm volatile("mov %0, %1\n\txpaci %0" : "=&r"(out) : "r"(in));
    return out;
}

static unsigned long xpacd(unsigned long in)
{
    unsigned long out;
    asm volatile("mov %0, %1\n\txpacd %0" : "=&r"(out) : "r"(in));
    return out;
}

static unsigned long pacia(unsigned long in)
{
    unsigned long out;
    asm volatile("pacia %0, %1" : "=r"(out) : "r"(in));
    return out;
}

static unsigned long autia(unsigned long in)
{
    unsigned long out;
    asm volatile("autia %0, %1" : "=r"(out) : "r"(in));
    return out;
}

int main(void)
{
    const unsigned long a = 0x123456789abcdef0UL;
    const unsigned long b = 0x0000000000001234UL;

    if (xpaci(a) != a || xpacd(a) != a ||
        xpaci(b) != b || xpacd(b) != b) {
        puts("FAIL: XPACI/XPACD changed an unauthenticated pointer");
        return 1;
    }
    if (pacia(a) != a || autia(a) != a) {
        puts("FAIL: PACIA/AUTIA are not no-ops without PAC support");
        return 1;
    }

    puts("PASS");
    return 0;
}
