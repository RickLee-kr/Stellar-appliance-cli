#!/usr/bin/env python3
import os
import pwd
import subprocess
import functools
import logging
import logging.handlers

LOG_DIR = "/var/log/aella"


def get_username():
    return pwd.getpwuid(os.getuid())[0]


def print_log(msg, logger, level=logging.INFO):
    print(msg)
    if logger:
        logger.log(level, msg)


def make_dir(target_dir, group=None, logger=None, root=False):
    cmd = "mkdir -p {}".format(target_dir)
    if root:
        cmd = "sudo " + cmd
    proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, shell=True)
    _, err = proc.communicate()
    if proc.returncode != 0:
        err_msg = err.decode("utf-8")
        if "Permission denied" in err_msg:
            user = get_username()
            if group is None:
                group = user  # use same group as user
            proc = subprocess.Popen("sudo usermod -a -G {} {}".format(group, user), shell=True)
            proc.communicate()
            if proc.returncode != 0:
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
    cmd = "touch {}".format(file_path)
    if root:
        cmd = "sudo " + cmd
    proc = subprocess.Popen(cmd, shell=True)
    proc.communicate()
    if proc.returncode != 0:
        print_log("Failed to create file {}".format(file_path), level=logging.ERROR)
        return False
    if owner != "root":
        cmd = "chown {} {}".format(owner, file_path)
        if root:
            cmd = "sudo " + cmd
        proc = subprocess.Popen(cmd, shell=True)
        proc.communicate()
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
    log_format = "%(asctime)-15s|%(levelname)s|%(thread)d|%(module)s|%(message)s"
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(log_format)
    handler = RotatingFileHandler(filename)
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
