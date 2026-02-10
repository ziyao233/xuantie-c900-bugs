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
