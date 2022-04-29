from pandare import Panda
from sys import argv
import socket

arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

#add 
approved_addrs = []

#PUT IP AND PORT YOU WANT TO REDIRECT TO HERE
redirect_addr = socket.inter_aton("")
redirect_port = 8080

@panda.ppp("syscalls2", "on_sys_connect_enter")
def on_sys_connect_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    if panda.in_kernel(cpu):
        return

    try:
        #fname = panda.read_str(cpu, fname_ptr)
        sockfd = panda.virtual_memory_read(cpu, argv_ptr, 4, fmt='int')
        sockaddr_fam = panda.virtual_memory_read(cpu, argv_ptr+4, 2, fmt='int')
        sockaddr_port = panda.virtual_memory_read(cpu, argv_ptr+6, 2, fmt='int')
        sockaddr_addr = panda.virtual_memory_read(cpu, argv_ptr+8, 4, fmt='int')
        sockaddr_zero = panda.virtual_memory_read(cpu, argv_ptr+12, 8, fmt='str')

    except ValueError: return
    sockaddr_addr = socket.inet_ntoa(sockaddr_addr)
    print("sockfd: ", sockfd)
    print("sockaddr_fam: ", sockaddr_fam)
    print("sockaddr_port: ", sockaddr_port)
    print("sockaddr_addr: ", sockaddr_addr)
    print("sockaddr_zero: ", sockaddr_zero)
        
    if sockaddr_addr not in approved_addrs:
        if panda.in_kernel(cpu):
            if redirect_port != sockaddr_port:
                panda.virtual_memory_write(cpu, argv_ptr+6, redirect_port)
            panda.virtual_memory_write(cpu, argv_ptr+8, redirect_addr)
        except ValueError: return

@panda.queue_blocking
def driver():
    print("Loading snapshot...")
    panda.revert_sync("root")
    print("Snapshot loaded. All done")
    panda.copy_to_guest("/host/images")
    panda.run_serial_command("./client")
    panda.end_analysis()
panda.run()
