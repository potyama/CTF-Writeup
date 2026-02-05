
from Crypto.Util.number import *
import base64
import os

flag = os.getenv("FLAG", "DUMMYD{DUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY}").encode()
flag1 = flag[:20]
flag2 = flag[20:40]
flag3 = flag[40:]

print(f"long_value = {bytes_to_long(flag1)}")
print(f'hex_string = "{flag2.hex()}"')
print(f'base64_string = "{base64.b64encode(flag3).decode()}"')