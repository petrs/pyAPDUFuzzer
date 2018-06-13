import sys

from utils.logging import error


def auto_int(x):
    return int(x, 0)


def raise_critical_error(component, exception):
    error(component,"{}:{}".format(type(exception), exception))
    sys.exit(1)
