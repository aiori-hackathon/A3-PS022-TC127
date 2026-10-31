"""Wait for a byte from the parent before replacing this process with a tool."""
import os
import sys


def main():
    fd = int(sys.argv[1])
    ready_fd = int(sys.argv[2])
    if sys.argv[3] != "--":
        raise SystemExit("Expected -- before child command")
    command = sys.argv[4:]
    if not command:
        raise SystemExit("Missing child command")
    # Tell the parent this process has reached the start barrier.
    os.write(ready_fd, b"R")
    os.close(ready_fd)
    marker = os.read(fd, 1)
    os.close(fd)
    if marker != b"1":
        raise SystemExit("Start gate cancelled")
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
