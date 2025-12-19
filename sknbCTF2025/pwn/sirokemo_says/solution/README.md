# 解法

```
└─(07:13:14 on main ✭)──> checksec chall                                                                                                                 ──(Tue,Nov25)─┘
[*] '/home/pppp4869/CTF/CTF-Writeup/sknbCTF2025/pwn/sirokemo_says/distfiles/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

まず、exit関数のリターンアドレスをmain関数に書き換え、再度main関数を呼び出す。

```
000000404020  000700000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
0000000000401166   411 FUNC    GLOBAL DEFAULT   14 main
```

