import os
import json
from threading import Lock

from .logging import debug


class FileWriter:
    def __init__(self, filename=None, fd=None):
        self.lock = Lock()
        self.fd = open(filename, "w") if filename else fd
        self.write_count = 0

    def print_to_file(self, data):
        with self.lock:
            self.fd.write("{}\n".format(data))
            if self.write_count > 1000:
                self.fd.flush()
                os.fsync(self.fd)
                self.write_count = 0
            else:
                self.write_count += 1

    def export_elem_as_json(self, elem):
        serialized_element = elem.serialize()
        debug("fuzzer", serialized_element)
        self.print_to_file("%s" % json.dumps(serialized_element))
