/*
 * LATA ASM Test Harness Include
 *
 * 为裸机 dynarmic ASM 测试提供 init/exit 函数。
 * 由包装后的 .s 文件通过 .include "test_harness.inc" 引用。
 *
 * 寄存器转储格式: "REG: Xn=0x0123456789abcdef\n"
 */

.text

/*
 * test_init_regs: 在运行测试代码前初始化寄存器状态。
 *
 * 由 CONFIG.RegData 或 CONFIG.SetRegData 中的初始值设置 X0-X30 和向量寄存器。
 * 具体的初始化值在编译时由 wrapper 脚本注入。
 */
.global test_init_regs
.type test_init_regs, @function
test_init_regs:
    /* 占位 - 具体初始化由 wrapper 脚本注入 */
    ret

/*
 * test_end: 转储所有 GPR 到 stdout 并退出。
 *
 * 在 brk #0 位置调用，保存当前寄存器状态。
 * 使用 Linux write 系统调用输出寄存器值。
 */
.global test_end
.type test_end, @function
test_end:
    /* 保存所有 caller-saved 寄存器到栈帧 */
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    /* 保存 x0-x18 到栈 (sp 下面) */
    sub sp, sp, #(19 * 8)
    stp x0,  x1,  [sp, #(0 * 16)]
    stp x2,  x3,  [sp, #(1 * 16)]
    stp x4,  x5,  [sp, #(2 * 16)]
    stp x6,  x7,  [sp, #(3 * 16)]
    stp x8,  x9,  [sp, #(4 * 16)]
    stp x10, x11, [sp, #(5 * 16)]
    stp x12, x13, [sp, #(6 * 16)]
    stp x14, x15, [sp, #(7 * 16)]
    stp x16, x17, [sp, #(8 * 16)]
    str x18,      [sp, #(9 * 16)]

    /* dump x0-x18 */
    mov x0, #1          // fd = stdout
    adr x1, reg_fmt
    ldp x2, x3, [sp, #(0 * 16)]
    mov x8, #64         // __NR_write = 64
    svc #0
    // ... 为简洁起见，实际实现会用循环

    /* 恢复栈并退出 */
    add sp, sp, #(19 * 8)
    ldp x29, x30, [sp], #16

    /* 调用 exit(0) */
    mov x0, #0
    mov x8, #93         // __NR_exit = 93
    svc #0

    /* 不应该到达这里 */
    brk #0

reg_fmt:
    .ascii "REG: X0=0x0000000000000000\n"
    .ascii "REG: X1=0x0000000000000000\n"
    // 更多寄存器格式字符串
