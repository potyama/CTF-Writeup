from pwn import *
import hashlib

HOST = "verbal-sleep.picoctf.net"
PORT = 60196

def check_algo(hash):
    n = len(hash)
    if n == 32:
        return "md5"
    if n == 40:
        return "sha1"
    if n == 64:
        return "sha256"
    raise ValueError(f"Unsupported hash length: {n}")
    
def hashcrack(algo, hash):
    if algo == "md5":
        with open("./rockyou.txt", "r") as f:
            for password in f:
                password = password.strip()
                hashed_password = hashlib.md5(password.encode()).hexdigest()
                if hashed_password == hash:
                    print(f"Found: {password}")
                    return password
    if algo == "sha1":
        with open("./rockyou.txt", "r") as f:
            for password in f:
                password = password.strip()
                hashed_password = hashlib.sha1(password.encode()).hexdigest()
                if hashed_password == hash:
                    print(f"Found: {password}")
                    return password
    if algo == "sha256":
        with open("./rockyou.txt", "r") as f:
            for password in f:
                password = password.strip()
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                if hashed_password == hash:
                    print(f"Found: {password}")
                    return password
io = remote(HOST, PORT)

# Stage1
io.recvuntil(b"We have identified a hash: ")
hash = io.recvline().strip().decode()

io.sendlineafter(b"Enter the password for identified hash: ", hashcrack(check_algo(hash), hash))

# Stage2
io.recvuntil(b"Crack this hash: ")
hash = io.recvline().strip().decode()

io.sendlineafter(b"Enter the password for the identified hash: ", hashcrack(check_algo(hash), hash))

# Stage3
io.recvuntil(b"Crack this hash: ")
hash = io.recvline().strip().decode()

io.sendlineafter(b"Enter the password for the identified hash: ", hashcrack(check_algo(hash), hash))
io.interactive()