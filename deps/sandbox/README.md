# Privsep sandbox for h2o

This code adds sandboxing functionality to h2o. The sandbox consists of two main
parts: a privileged process that is responsible for mediating all access between
the non-privileged process (h2o workers) and the global namespaces associated with
the operating systems e.g.: network stack, file system, system V IPC mechaniss to
name a few.

The child process will be restricted using operating system provided primitives.
On Linux we are using seccomp, and on FreeBSD we are using capsicum. This restricts
the syscall surface available to the h2o workers, forcing it to go through the
privileged process for access to such resources. This sandbox design is inspired
by OpenSSH. Certain utility functions and macros have been taken from both Chromium
and OpenSSH.

## Credits

The following people wrote/contributed to the OpenSSH prvisep code which we took
some of the file description transport, and seccomp debugging code:

 * Copyright (c) 2003 Can Erkin Acar
 * Copyright (c) 2003 Anil Madhavapeddy <anil@recoil.org>

Some of the macros to determine the machine architecture (currently stored in
sandbox.h) were taken from the Chromium project.
