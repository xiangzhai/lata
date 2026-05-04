/**
 * LATA ASM Test Harness - Linux AArch64 user-space test runtime.
 *
 * 为裸机 dynarmic ASM 测试提供 Linux 进程环境：
 * 1. test_init_regs: 从链接时嵌入的配置初始化寄存器
 * 2. test_end: 将寄存器状态 dump 到 stdout
 *
 * 编译: aarch64-linux-gnu-gcc -c test_harness.c -o test_harness.o
 * 链接: aarch64-linux-gnu-ld test.o test_harness.o -o test.elf
 *
 * 注意：本 harness 通过 ".include test_harness.inc" 被包装后的 test .s 文件引用。
 * 寄存器转储使用汇编实现以确保在寄存器被修改之前保存。
 */

#include <stdint.h>

/* 寄存器转储结构 */
struct reg_state {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
};

/* QEMU 用户模式不会真的输出，需要SVC syscall */
static void sys_write(int fd, const void *buf, unsigned long count) {
    register long x8 __asm__("x8") = 64;   // __NR_write
    register long x0 __asm__("x0") = fd;
    register const void *x1 __asm__("x1") = buf;
    register unsigned long x2 __asm__("x2") = count;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0), "r"(x1), "r"(x2) : "memory");
}

static void sys_exit(int code) {
    register long x8 __asm__("x8") = 93;  // __NR_exit
    register long x0 __asm__("x0") = code;
    __asm__ volatile("svc #0" : : "r"(x8), "r"(x0));
}

/* 十六进制数字转换 */
static char hex_digit(uint8_t n) {
    return n < 10 ? '0' + n : 'a' + (n - 10);
}

/* 将 64位值以十六进制输出到缓冲区 */
static void format_hex(char *buf, uint64_t val) {
    for (int i = 15; i >= 0; i--) {
        buf[15 - i] = hex_digit((val >> (i * 4)) & 0xf);
    }
    buf[16] = '\0';
}

static char hex_buf[64];

/* 输出一行 "REG: Xn = 0x..." */
static void dump_reg(const char *name, uint64_t val) {
    int i = 0;
    while (name[i]) { i++; }  // 计算名称长度 (在 test_end 汇编中调用)
    // 名称由汇编传入，直接输出
    format_hex(hex_buf, val);
    sys_write(1, name, 4);  // "REG:"
    // 实际实现在汇编中完成
}

/* 退出时调用 */
void __attribute__((noreturn)) test_exit(int code) {
    sys_exit(code);
    __builtin_unreachable();
}
