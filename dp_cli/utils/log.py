#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
from typing import Optional

import os
import pwd
import subprocess
import functools
import logging
import logging.handlers

LOG_DIR = "/var/log/aella"


def get_username():
    return pwd.getpwuid(os.getuid())[0]


def print_log(msg: str, logger: logging.Logger | None = None, level: int = logging.INFO) -> None:
    print(msg)
    if logger:
        logger.log(level, msg)


def make_dir(target_dir, group=None, logger=None, root=False):
    target_path = Path(target_dir)
    try:
        if root:
            proc = subprocess.run(
                ["sudo", "mkdir", "-p", str(target_path)],
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        else:
            target_path.mkdir(parents=True, exist_ok=True)
            proc = subprocess.CompletedProcess([], 0, "", "")
    except PermissionError:
        proc = subprocess.run(
            ["sudo", "mkdir", "-p", str(target_path)],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception as e:
        err_msg = str(e)
        print_log("Failed to create directory {}: {}".format(target_dir, err_msg), logger, level=logging.ERROR)
        return False
    
    if proc.returncode != 0:
        err_msg = proc.stderr
        if "Permission denied" in err_msg:
            user = get_username()
            if group is None:
                group = user  # use same group as user
            proc2 = subprocess.run(
                ["sudo", "usermod", "-a", "-G", group, user],
                check=False,
            )
            if proc2.returncode != 0:
                print_log("Failed to add {} into {} group".format(user, group), logger, level=logging.ERROR)
                return False
        else:
            print_log("Failed to create directory {}: {}".format(target_dir, err_msg), logger, level=logging.ERROR)
            return False
    return True


def ensure_file(file_path, root=False, owner=None):
    if owner is None:
        owner = get_username()
    base_dir = os.path.dirname(file_path)
    if not make_dir(base_dir, root=root):
        print_log("Failed to create directory {}".format(base_dir), level=logging.ERROR)
        return False
    file_path_obj = Path(file_path)
    try:
        if root:
            proc = subprocess.run(
                ["sudo", "touch", str(file_path_obj)],
                check=False,
            )
        else:
            file_path_obj.touch(exist_ok=True)
            proc = subprocess.CompletedProcess([], 0)
    except PermissionError:
        proc = subprocess.run(
            ["sudo", "touch", str(file_path_obj)],
            check=False,
        )
    except Exception:
        proc = subprocess.run(
            ["sudo", "touch", str(file_path_obj)],
            check=False,
        )
    
    if proc.returncode != 0:
        print_log("Failed to create file {}".format(file_path), level=logging.ERROR)
        return False
    if owner != "root":
        chown_cmd = ["chown", owner, str(file_path_obj)]
        if root:
            chown_cmd = ["sudo"] + chown_cmd
        proc = subprocess.run(chown_cmd, check=False)
        if proc.returncode != 0:
            print_log("Failed to change owner of file {}".format(file_path), level=logging.ERROR)
            return False
    return True


class RotatingFileHandler(logging.handlers.RotatingFileHandler):
    def __init__(self, filename, *args, **kwargs):
        make_dir(os.path.dirname(filename), group="syslog")
        super(RotatingFileHandler, self).__init__(filename, *args, **kwargs)


def get_logger(log_name):
    filename = os.path.join(LOG_DIR, "{}.log".format(log_name))
    logger = logging.getLogger(log_name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)-15s|%(levelname)s|%(thread)d|%(module)s|%(message)s"
    )
    handler = RotatingFileHandler(
        filename,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOG = get_logger("aella_cli")


def log_cmd(f):
    @functools.wraps(f)
    def wrapper(*args, **kwds):
        LOG.info('Run command: %s %s', f.__name__[3:], " ".join(args[1:]))
        return f(*args, **kwds)
    return wrapper
