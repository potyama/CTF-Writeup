from z3 import *
import struct 
from Crypto.Util.strxor import strxor

def next(state):
    state = (state ^ (state << 13)) % 2**64
    state = (state ^ (state >> 7)) % 2**64
    state = (state ^ (state << 17)) % 2**64
    return state


def z3_next(state):
    state = (state ^ (state << 13))
    state = (state ^ LShR(state,7))
    state = (state ^ (state << 17))
    return state

enc = "142d35c86db4e4bb82ca5965ca1d6bd55c0ffeb35c8a5825f00819821cd775c4c091391f5eb5671b251f5722f1b47e539122f7e5eadc00eee8a6a631928a0c14c57c7e05b6575067c336090f85618c8e181eeddbb3c6e177ad0f9b16d23c777b313e62b877148f06014e8bf3bc156bf88eedd123ba513dfd6fcb32446e41a5b719412939f5b98ffd54c2b5e44f4f7a927ecaff337cddf19fa4e38cbe01162a1b54bb43b0678adf2801d893655a74c656779f9a807c3125b5a30f4800a8"
key_range = 2*len(enc)//3
enc_key = enc[:key_range]
enc_flag = enc[key_range:] 


seed_state = BitVec('seed_state',64)
ct_u64blocks = []
for i in range(len(enc_key)//16):
        block_hex = enc_key[i*(16):(i+1)*16]
        block_bytes = bytes.fromhex(block_hex)
        block_u64 = struct.unpack("<Q", block_bytes)[0]
        ct_u64blocks.append(BitVecVal(block_u64, 64))

s = Solver()
for r, ct_block in enumerate(ct_u64blocks):
        state = seed_state
        for _ in range(r+1):
            state = z3_next(state)
        pt_block = state ^ ct_block
        for byte_index in range(8):
            pt_byte = Extract(8 * (byte_index+1) - 1, 8 * byte_index, pt_block)
            is_digit = And(pt_byte >= 0x30, pt_byte <= 0x39)
            is_lower = And(pt_byte >= 0x61, pt_byte <= 0x66)
            s.add(Or(is_digit, is_lower))

init_state = 0
if s.check() == sat:
    init_state = s.model()[seed_state].as_long()
    print("[+] init_state: "+hex(init_state))
else:
    print("no")
    raise SystemExit(1)

state = init_state
len_plain = len(enc)//2
plain = b""
for i in range(0, len(enc), 16):
    state = next(state)
    plain_bytes = bytes.fromhex(enc[i:i+16])
    if len(plain_bytes) < 8:
         plain_bytes += b'\x00'*(8-len(plain_bytes))
    key_block = struct.unpack("<Q", plain_bytes)[0]
    plain += struct.pack("<Q", key_block^state)

plain = plain[:len_plain]
key = bytes.fromhex(plain[:key_range//2].decode())
xor_enc = plain[key_range//2:]

print(strxor(key, xor_enc).decode())