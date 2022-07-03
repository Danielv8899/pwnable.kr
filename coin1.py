from pwn import *
import sys

sys.setrecursionlimit(2000)
N = 0
C = 0
b = b""

arr = []

server = ['0',9007]

p = remote(server[0],server[1])

sleep(3)
p.recvuntil(b"  - Ready? starting in 3 sec... -\n")
p.recvline().split(b" ")
b = p.recvline().split(b" ")
N = int(b[0].split(b'=')[1])
C = int(b[1].split(b'=')[1].strip())

arr = []


def restart():
        b = p.recvline().split(b" ")
        print b
        try:
                N = int(b[0].split(b'=')[1])
        except:
                print p.recvline()
                p.close()

        C = int(b[1].split(b'=')[1].strip())

        arr = []

        get_array(arr)

        binary_search(arr,0,N)

def get_array(arr):
        for i in range(N):
                arr += [str(i)]

def binary_search(arr,low,high):
        if high >= low:
                mid = (high + low) // 2
                payload = b""

                for x in arr[mid:high]:
                        payload += bytes(x)
                        payload += b" "
                p.sendline(payload)
                res = p.recvline()
                try:
                        res = int(res.strip())
                except:
                        print(res)
                        restart()
                if res % 10 == 0:
                        binary_search(arr,low,mid)
                else:
                        binary_search(arr,mid,high)


get_array(arr)
binary_search(arr,0,N+1)

p.close()