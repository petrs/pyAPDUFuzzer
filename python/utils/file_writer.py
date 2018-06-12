from threading import Lock
import json
from const import ISO7816CODES
import sys

class FileWriter:
    def __init__(self, filename):
        self.lock = Lock()
        self.fd = open(filename,"w")

    def print_to_file(self, data):
        with self.lock:
            self.fd.write("{}\n".format(data))

    def export_json(self, in_cla, in_ins, in_p1, in_p2, in_len, in_data, out_sw1, out_sw2, out_data, timing):
        try:
            statuscode = (out_sw1<<8)+out_sw2
            out_status_str =  ISO7816CODES[statuscode]
        except:
            out_status_str = "UNKNOWN"
        result = {
            "in_cla": "{:02x}".format(in_cla),
            "in_ins": "{:02x}".format(in_ins),
            "in_p1": "{:02x}".format(in_p1),
            "in_p2": "{:02x}".format(in_p2),
            "in_data": "",
            "in_cmd": "{:02x}{:02x}{:02x}{:02x}{:02x}".format(in_cla, in_ins, in_p1, in_p2, in_len),
            "out_status":"{:02x}{:02x}".format(out_sw1, out_sw2),
            "out_status_str": out_status_str,
            "out_data": "".join(["{:02x}".format(d) for d in out_data]),
            "timing": timing*1000
        }
        print("%s" % json.dumps(result))
        self.print_to_file("%s" % json.dumps(result))
