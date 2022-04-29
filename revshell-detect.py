from pandare import Panda
from sys import argv
import re

arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

bad_procs = {"sh", "nc", "telnet"}
re_ip = re.compile('^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$')

@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    if panda.in_kernel(cpu):
        return

    try:
        fname = panda.read_str(cpu, fname_ptr)
        argv_ptrlist = panda.virtual_memory_read(cpu, argv_ptr, 80, fmt='ptrlist')
    except ValueError: return
    argv = []
    for ptr in argv_ptrlist:
        if ptr == 0: break
        try:
            argv.append(panda.read_str(cpu, ptr))
        except ValueError:
            argv.append(f"(error)")
    for x in argv:
        print("EXECVE: ", x)
        match = re_ip.match(x)
        if match != None:
            print("ALERT: ATTEMPTING TO REACH REMOTE IP")
        for p in bad_procs:
            if p == x:
                #TODO: Make network jail to stop these processes
                print("ALERT: BAD PROCESS DETECTED")


@panda.queue_blocking
def driver():
    print("Loading snapshot...")
    panda.revert_sync("root")
    print("Snapshot loaded. All done")
    panda.run_serial_cmd("ls")
    panda.run_serial_cmd("nc 0.0.0.0")
    panda.run_serial_cmd("nc 255.255.255.256")
    panda.run_serial_cmd("nc 255.255.255.254")
    panda.end_analysis()
panda.run()
