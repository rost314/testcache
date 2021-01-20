#!/usr/bin/env python3
from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
                             ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.syscall import (SYSCALL_NAMES, SYSCALL_PROTOTYPES,
                            FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES)
from ptrace.func_call import FunctionCall, FunctionCallOptions
from sys import stderr, exit
from optparse import OptionParser
from logging import getLogger, error
from pprint import pprint
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.ctypes_tools import formatAddress
from ptrace.debugger.process import PtraceProcess
from ptrace.syscall import PtraceSyscall
from ptrace.func_arg import FunctionArgument
import re
import os

# ToDo: drop Application. It's too restrictive.


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

    def parseOptions(self):
        parser = OptionParser(
            usage="%prog [options] -- program [arg1 arg2 ...]")
        self.createCommonOptions(parser)

        self.options, self.program = parser.parse_args()

        self.processOptions()

    def ignoreSyscall(self, syscall: PtraceSyscall):
        # A whitelist for file open etc would be easier, but first we need to find those functions
        ignore = ["arch_prctl", "mprotect", "pread64", "pwrite64", "read", "write",
                  "mmap", "munmap", "brk", "sbrk"]
        if syscall.name in ignore:
            return True

        return False

    def readCString(self, process: PtraceProcess, addr) -> str:
        data, truncated = process.readCString(addr, 5000)
        if truncated:
            return None  # fail!
        return data

    def readFilename(self, syscall: PtraceSyscall, argument_name: str) -> str:
        cstring: str = self.readCString(
            syscall.process, syscall[argument_name].value)
        filename: str = os.fsdecode(cstring)
        return filename

    def displaySyscall(self, syscall: PtraceSyscall):
        error(f"{syscall.format():80s} = {syscall.result_text}")

        if syscall.name == "openat":
            flags: int = syscall['flags'].value
            O_READONLY: int = 0
            O_CLOEXEC: int = 0o2000000
            readonly: bool = flags == O_READONLY or flags == O_CLOEXEC
            filename = self.readFilename(syscall, 'filename')
            if readonly:
                error(f"> cache additional file: {filename}")
            else:
                error(f"> Abort: Not readonly access to {filename}")

        if syscall.name == "access":
            filename = self.readFilename(syscall, 'filename')
            error(f"> cache file access rights: {filename}")

        if syscall.name == "stat":
            filename = self.readFilename(syscall, 'filename')
            error(f"> cache stat: {filename}")

        if syscall.name == "fstat":
            error(f"> cache stat: (ToDo: track file descriptors)")

    def syscallTrace(self, process: PtraceProcess):
        # First query to break at next syscall
        self.prepareProcess(process)

        while True:
            # No more process? Exit
            if not self.debugger:
                break

            # Wait until next syscall enter
            try:
                event = self.debugger.waitSyscall()
            except ProcessExit as event:
                self.processExited(event)
                continue
            except ProcessSignal as event:
                event.display()
                event.process.syscall(event.signum)
                continue
            except NewProcessEvent as event:
                self.newProcess(event)
                continue
            except ProcessExecution as event:
                self.processExecution(event)
                continue

            # Process syscall enter or exit
            self.syscall(event.process)

    def syscall(self, process: PtraceProcess):
        state = process.syscall_state
        syscall = state.event(self.syscall_options)
        if syscall and syscall.result is not None:
            # Display syscall exit since now we have the exit code
            self.displaySyscall(syscall)

        # proceed with syscall
        process.syscall()

    def processExited(self, event):
        # Display syscall which has not exited
        state = event.process.syscall_state
        if (state.next_event == "exit") and state.syscall:
            self.displaySyscall(state.syscall)

        # Display exit message
        error(f"*** {event} ***")

    def prepareProcess(self, process: PtraceProcess):
        process.syscall()
        process.syscall_state.ignore_callback = self.ignoreSyscall

    def newProcess(self, event):
        process = event.process
        error("*** New process %s ***" % process.pid)
        self.prepareProcess(process)
        process.parent.syscall()

    def processExecution(self, event):
        process = event.process
        error("*** Process %s execution ***" % process.pid)
        process.syscall()

    def runDebugger(self):
        # Create debugger and traced process
        self.setupDebugger()
        process = self.createProcess()
        if not process:
            return

        self.syscall_options = FunctionCallOptions(
            write_types=True,
            write_argname=True,
            string_max_length=200,
            replace_socketcall=False,
            write_address=True,
            max_array_count=50,
        )

        self.syscallTrace(process)

    def main(self):
        self.debugger = PtraceDebugger()
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


if __name__ == "__main__":
    TCache().main()
