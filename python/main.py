#!/usr/bin/env python3

import os
import sys
import logging
import time
import json
import time
import binascii
import argparse
#logging.basicConfig(level=logging.DEBUG)

# 3rd party (PyScard)
from smartcard.System import readers
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.SWExceptions import SWException

# LL Smartcard
import llsmartcard.apdu as APDU
from llsmartcard.apdu import APDU_STATUS, APPLET
from llsmartcard.card import SmartCard, CAC

from const import ISO7816CODES


INS_START = 0x00
INS_END = 0xFF
MODE_TRUST = True

def export_json(fd, cla, ins, p1, p2, length, sw1, sw2, out_data, timing):
    try:
        statuscode = (sw1<<8)+sw2
        out_status_str =  ISO7816CODES[statuscode]
    except:
        out_status_str = "UNKNOWN"
    result = {
        "in_cla": "{:02x}".format(cla),
        "in_ins": "{:02x}".format(ins),
        "in_p1": "{:02x}".format(p1),
        "in_p2": "{:02x}".format(p2),
        "in_data": "",
        "in_cmd": "{:02x}{:02x}{:02x}{:02x}{:02x}".format(cla, ins, p1, p2, length),
        "out_status":"{:02x}{:02x}".format(sw1, sw2),
        "out_status_str": out_status_str,
        "out_data": "".join(["{:02x}".format(d) for d in out_data]),
        "timing": timing*1000
    }
    print("%s\n" % json.dumps(result, sort_keys=True))
    fd.write("%s\n" % json.dumps(result))

def insert_trial(cla, ins, sw1, sw2):
    """
        Insert a trial with status word response into our structures
    """
    global cla_sw_ins, sw_ins_cla

    sw = sw1 << 8 | sw2

    # Depth = 1
    if cla not in cla_sw_ins:
        cla_sw_ins[cla] = {}
    if sw not in sw_ins_cla:
        sw_ins_cla[sw] = {}

    # Depth = 2
    if ins not in sw_ins_cla[sw]:
        sw_ins_cla[sw][ins] = []
    if ins not in cla_sw_ins[cla]:
        cla_sw_ins[cla][sw] = []

    # Add the nugget
    sw_ins_cla[sw][ins].append(cla)
    cla_sw_ins[cla][sw].append(ins)


"""
    Functions for interacting with the card
"""
def send_apdu(card, apdu_to_send):
    """
        Send an APDU to the card, and hadle errors appropriately
    """
    timing = -1
    str = "Trying : ", [hex(i) for i in apdu_to_send]
    logging.debug(str)
    try:

        start = time.time()
        (data, sw1, sw2) = card._send_apdu(apdu_to_send)
        end = time.time()
        timing = end - start

    except SWException as e:
        # Did we get an unsuccessful attempt?
        logging.info(e)
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        print(e)
        logging.warn("Oh No! Pyscard crashed...")
        (data, sw1, sw2) = ([], 0xFF, 0xFF)

    str = "Got : ", data, hex(sw1), hex(sw2)
    logging.debug(str)

    return (data, sw1, sw2, timing)

def fuzzer(card, fd, args=None):
    valid_cla = []

    print("Enumerating valid classes...")
    for cla in range(0xFF + 1):
        apdu_to_send = [cla, 0x00, 0x00, 0x00]

        (data, sw1, sw2, timing) = send_apdu(card, apdu_to_send)

        # unsupported class is 0x6E00
        if (sw1 == 0x6E) and (sw2 == 0x00):
            continue
        else:
            valid_cla.append(cla)

    print("Found %d valid command classes: " % len(valid_cla))
    if len(valid_cla) == 256:
        print("Class Checking seems to be disabled")
        valid_cla = [0x0B]
    else:
        for cla in valid_cla:
            print("%s" % hex(cla))

    print("Brute forcing every command for each class...")
    invalid_class = []
    for cla in valid_cla:
        for ins in range(INS_START,INS_END + 1):
            (sw1, sw2) = fuzz_instruction(card, fd, cla, ins)

            if (sw1,sw2) ==  (0x6E,0x00):
                invalid_class.append([cla, ins])


    for dat in invalid_class:
        for cla in range(0xFF + 1):
            if cla not in valid_cla:
                fuzz_instruction(card, fd, cla, dat[1])

    print("Done.")

def fuzz_instruction(card, fd, cla, ins):
    for p1 in range(0xFF + 1):
        for p2 in range(0xFF + 1):
            apdu_to_send = [cla, ins, p1, p2]
            (data, sw1, sw2, timing) = send_apdu(card, apdu_to_send)
            export_json(fd, cla, ins, p1, p2, 0,sw1, sw2, data, timing)
            if (sw1,sw2) ==  (0x6E,0x00):
                return (sw1,sw2)

            if (sw1,sw2) ==  (0x6D,0x00) and MODE_TRUST:
                return (sw1,sw2)
    return (0,0)

def prefix_fuzzing(fd):
    # get readers
    reader_list = readers()
    # Let the user the select a reader
    if len(reader_list) > 1:
        print("Please select a reader")
        idx = 0
        for r in reader_list:
            print("  %d - %s"%(idx,r))
            idx += 1

        reader_idx = -1
        while reader_idx < 0 or reader_idx > len(reader_list)-1:
            reader_idx = int(raw_input("Reader[%d-%d]: "%(0,len(reader_list)-1)))

        reader = reader_list[reader_idx]
    else:
        reader = reader_list[0]

    print("Using: %s" % reader)

    # create connection
    connection = reader.createConnection()
    connection.connect()

    # do stuff with CAC
    card = CAC(connection)

    # Call our fuzzer
    try:
        fuzzer(card, fd)
    finally:
        fd.close()

def auto_int(x):
    return int(x, 0)

def main():
    global INS_START, INS_END
    parser = argparse.ArgumentParser(description='Fuzz smartcard api.')
    parser.add_argument('--start_ins', dest='start_ins', action='store', type=auto_int,
                        default=0x00, help='Instruction to start fuzzing at')
    parser.add_argument('--end_ins', dest='end_ins', action='store', type=auto_int,
                        default=0xff, help='Instruction to stop fuzzing at')
    parser.add_argument('--output', dest='output_file', action='store', type=str,
                        default="result/{}-export.json".format(str(time.time()).replace(".","")), help='File to output results to')
    args = parser.parse_args()
    INS_START = args.start_ins
    INS_END = args.end_ins
    try:
        os.mkdir("result")
    except:
        pass
    fd = open(args.output_file, "w")
    prefix_fuzzing(fd)

if __name__ == "__main__":
    main()
