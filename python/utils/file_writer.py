import json
from threading import Lock

from utils.logging import debug


class FileWriter:
    def __init__(self, filename):
        self.lock = Lock()
        self.fd = open(filename, "w")
        self.write_count = 0

    def print_to_file(self, data):
        with self.lock:
            self.fd.write("{}\n".format(data))
            if self.write_count > 1000:
                self.fd.fsync()
                self.write_count = 0
            else:
                self.write_count += 1

    def export_elem_as_json(self, elem):
        serialized_element = elem.serialize()
        debug("fuzzer", serialized_element)
        self.print_to_file("%s" % json.dumps(serialized_element))
