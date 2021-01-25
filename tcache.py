#!/usr/bin/env python3
import hashlib
import os
import re
import os.path

from errno import EPERM
from logging import error, getLogger
from optparse import OptionParser
from pprint import pprint
from sys import exit, stderr

from ptrace import PtraceError
from ptrace.ctypes_tools import formatAddress
from ptrace.debugger import (Application, NewProcessEvent, ProcessExecution,
                             ProcessExit, ProcessSignal, PtraceDebugger)
from ptrace.debugger.process import PtraceProcess
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.func_arg import FunctionArgument
from ptrace.func_call import FunctionCall, FunctionCallOptions
from ptrace.syscall import (FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES,
                            SYSCALL_NAMES, SYSCALL_PROTOTYPES, PtraceSyscall)

# ToDo: drop Application. It's too restrictive.
# ToDo: tcache and testcache are already reserved on GitHub.
#       bincache/bcache? genericcache?


class Inputs:
    """Holds a collection of all inputs which should lead to the same output"""
    files_to_hash = dict()  # path -> hash
    files_to_stat = dict()  # path -> stat

    def cache_additional_file(self, filename: str) -> None:
        self.files_to_hash[filename] = Utils.get_digest(filename)

    def cache_stat(self, filename: str) -> None:
        try:
            stat_result: os.stat_result = os.stat(filename)
        except FileNotFoundError:
            stat_result = None

        self.files_to_stat[filename] = stat_result

    def print(self) -> None:
        for file, digest in self.files_to_hash.items():
            print(f"hash: {file} = {digest}")

        for file, stat_result in self.files_to_stat.items():
            print(f"stat: {file} = {stat_result}")


class Utils:
    def readCString(process: PtraceProcess, addr) -> str:
        """Read C-String from process memory space at addr and return it."""
        data, truncated = process.readCString(addr, 5000)
        if truncated:
            return None  # fail in an obvious way for now
        return data

    # Surprisingly common use case
    def readFilenameFromSyscallParameter(syscall: PtraceSyscall, argument_name: str) -> str:
        cstring: str = Utils.readCString(
            syscall.process, syscall[argument_name].value)
        filename: str = os.fsdecode(cstring)
        return filename

    def get_digest(file_path: str) -> str:
        # Reuse stat call? Usually there was a stat call before this.
        if not os.path.exists(file_path):
            return None

        h = hashlib.sha256()

        with open(file_path, 'rb') as file:
            while True:
                # Reading is buffered, so we can read smaller chunks.
                chunk = file.read(h.block_size)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()


class SyscallListener:
    # In theory this class could be made ptrace independent.
    # But thats a huge amount of wrappers.
    # And what's even the point? This handles Linux specific syscalls anyway.

    inputs: Inputs

    # stdout, stderr... but mixed... puh...
    output: int

    filedescriptor_to_path = dict()

    def __init__(self):
        self.inputs = Inputs()
        return

    def ignoreSyscall(syscall: PtraceSyscall) -> bool:
        # A whitelist for file open etc would be easier, but first we need to find those interesting functions
        ignore = ["arch_prctl", "mprotect", "pread64", "pwrite64", "read", "write",
                  "mmap", "munmap", "brk", "sbrk"]
        return syscall.name in ignore

    def displaySyscall(syscall: PtraceSyscall) -> None:
        print(f"{syscall.format():80s} = {syscall.result_text}")

    def onSignal(self, event) -> None:
        # ProcessSignal has “signum” and “name” attributes
        # Note: ProcessSignal has a display() method to display its content.
        #       Use it just after receiving the message because it reads process
        #       memory to analyze the reasons why the signal was sent.
        return

    def onProcessExited(self, event: ProcessExit) -> None:
        # process exited with an exitcode, killed by a signal or exited abnormally
        # Note: ProcessExit has “exitcode” and “signum” attributes (both can be None)
        state = event.process.syscall_state
        if (state.next_event == "exit") and state.syscall:
            # Process was killed by a syscall
            SyscallListener.displaySyscall(state.syscall)

        # Display exit message
        error(f"*** {event} ***")

    def onNewProcessEvent(self, event: NewProcessEvent) -> None:
        # new process created, e.g. after a fork() syscall
        # use process.parent attribute to get the parent process.
        process = event.process
        error("*** New process %s ***" % process.pid)
        self.prepareProcess(process)

    def onProcessExecution(self, event) -> None:
        process = event.process
        error("*** Process %s execution ***" % process.pid)

    def onSyscall(self, process: PtraceProcess):
        state = process.syscall_state
        syscall: PtraceSyscall = state.event(FunctionCallOptions(
            write_types=True,
            write_argname=True,
            string_max_length=200,
            replace_socketcall=False,
            write_address=True,
            max_array_count=50,
        ))
        if syscall and syscall.result is not None and not SyscallListener.ignoreSyscall(syscall):
            SyscallListener.displaySyscall(syscall)

            if syscall.name == "openat":
                flags: int = syscall['flags'].value
                O_READONLY: int = 0
                O_CLOEXEC: int = 0o2000000
                readonly: bool = flags == O_READONLY or flags == O_CLOEXEC
                filename = Utils.readFilenameFromSyscallParameter(
                    syscall, 'filename')
                if readonly:
                    print(f"> cache additional file: {filename}")
                    self.inputs.cache_additional_file(filename)
                else:
                    print(f"> Abort: Not readonly access to {filename}")

                fd: int = syscall.result
                self.filedescriptor_to_path[fd] = filename
                print(f"> Tracking fd: {fd} = {filename}")

            if syscall.name == "access":
                filename = Utils.readFilenameFromSyscallParameter(
                    syscall, 'filename')
                print(f"> cache file access rights: {filename}")
                # for now just cache the entire file
                self.inputs.cache_additional_file(filename)

            if syscall.name == "stat":
                filename = Utils.readFilenameFromSyscallParameter(
                    syscall, 'filename')

                # Not sure it's possible to parse the stat structure here.
                # It has different members depending on a myriad of different things.
                # Just use the python os stats call at this point?
                addr: int = syscall['statbuf'].value

                print(f"> cache stat: {filename}")
                self.inputs.cache_stat(filename)

            if syscall.name == "fstat":
                fd: int = syscall['fd'].value
                print(f"> fstat of {fd}")
                self.inputs.cache_stat(self.filedescriptor_to_path[fd])
                print(f"> cache fstat: {self.filedescriptor_to_path[fd]}")

            if syscall.name == "close":
                fd: int = syscall['fd'].value
                print(f"> fd closed: {self.filedescriptor_to_path[fd]}")
                del self.filedescriptor_to_path[fd]


class TCache(Application):

    def __init__(self):
        Application.__init__(self)

        self.parseOptions()

        self._output = None

        # Normal log level:
        self.options.debug = False
        self.options.verbose = False
        self.options.quiet = False
        self._setupLog(stderr)

        self.syscall_listener = SyscallListener()

    def parseOptions(self):
        parser = OptionParser(
            usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)

        self.options, self.program = parser.parse_args()

        self.processOptions()

    def runDebugger(self):
        """Debug process and trigger syscall_listener on every syscall"""

        # Create stopped process (via fork followed by PTRACE_TRACEME) with given parameters
        try:
            pid: int = self.createChild(self.program)
            process: PtraceProcess = self.debugger.addProcess(
                pid, is_attached=True)
        except (ProcessExit, PtraceError) as err:
            if isinstance(err, PtraceError) and err.errno == EPERM:
                error("ERROR: You are not allowed to trace child process!")
            else:
                error("ERROR: Process can no be attached!")
            return

        # Start process, but break at system calls
        process.syscall()

        # ToDo: what exactly does this condition test?
        while self.debugger:
            try:
                # We have set breakpoints to occure on syscalls.
                # Therefore breakpoint are handled by onSyscall.
                breakpoint = self.debugger.waitSyscall()
                self.syscall_listener.onSyscall(breakpoint.process)
                # Docs: proceed with syscall??
                # Reality??: break at next one
                breakpoint.process.syscall()
            except ProcessExit as interrupt:
                self.syscall_listener.onProcessExited(interrupt)
            except ProcessSignal as signal:
                self.syscall_listener.onSignal(signal)
                signal.process.syscall(signal.signum)
            except NewProcessEvent as event:
                self.syscall_listener.onNewProcessEvent(event)
                event.process.parent.syscall()
            except ProcessExecution as exec:
                self.syscall_listener.onProcessExecution(exec)
                exec.process.syscall()

    def main(self):
        self.debugger = PtraceDebugger()
        self.debugger.traceFork()
        self.debugger.traceExec()
        self.debugger.traceClone()
        self.debugger.enableSysgood()

        try:
            self.runDebugger()
        except ProcessExit as event:
            self.processExited(event)
        except PtraceError as err:
            error("ptrace() error: %s" % err)
        except KeyboardInterrupt:
            error("Interrupted.")
        except PTRACE_ERRORS as err:
            writeError(getLogger(), err, "Debugger error")
        self.debugger.quit()

        print("\n\nEverything to cache:")
        self.syscall_listener.inputs.print()


if __name__ == "__main__":
    TCache().main()
