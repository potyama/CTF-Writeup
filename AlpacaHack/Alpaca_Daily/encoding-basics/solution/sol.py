from Crypto.Util.number import long_to_bytes
import base64

flag1 = 373502670300504551747111047082539140193958649718
flag2 = "346c5f6833785f6630726d61745f31735f636c33"
flag3 = "NG5fYjY0X3A0ZGQxbmdfaXNfY29vbH0="

flag = long_to_bytes(flag1).decode()
flag += bytes.fromhex(flag2).decode()
flag += base64.b64decode(flag3).decode()
print(flag)