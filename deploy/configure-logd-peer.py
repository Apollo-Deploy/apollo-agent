#!/usr/bin/env python3
"""Render numeric SO_PEERCRED policy from the installed logd service account.

Run as the Agent service owner (root with the supplied unit). Creates a private
new config; never overwrites an existing installation or prints credentials.
"""
import argparse
import json
import os
import pathlib
import pwd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("template", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    account = pwd.getpwnam("apollo-logd")
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise ValueError("apollo-logd must use its dedicated unprivileged account")
    config = json.loads(args.template.read_bytes())
    config.update(logd_socket="/run/apollo-logd/capture.sock",
                  logd_uid=account.pw_uid, logd_gid=account.pw_gid)
    destination = args.destination
    if not destination.is_absolute() or destination.parent.resolve() != destination.parent:
        raise ValueError("destination must have an absolute non-symlink parent")
    parent = destination.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError("config directory must be private and owned by the Agent service owner")
    data = (json.dumps(config, indent=2) + "\n").encode()
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        parent_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    main()
