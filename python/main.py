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

from fuzzer.prefix_fuzzer import PrefixFuzzer
from utils.file_writer import FileWriter
from utils.util import auto_int

def getCard():
    reader_list = readers()
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

    connection = reader.createConnection()
    connection.connect()

    card = CAC(connection)
    return card

def main():
    parser = argparse.ArgumentParser(description='Fuzz smartcard api.')
    parser.add_argument('--start_ins', dest='start_ins', action='store', type=auto_int,
                        default=0x00, help='Instruction to start fuzzing at')
    parser.add_argument('--end_ins', dest='end_ins', action='store', type=auto_int,
                        default=0xff, help='Instruction to stop fuzzing at')
    parser.add_argument('--output', dest='output_file', action='store', type=str,
                        default="result/{}-export.json".format(str(time.time()).replace(".","")), help='File to output results to')
    args = parser.parse_args()

    try:
        os.mkdir("result")
    except:
        pass

    card = getCard()
    file_writer = FileWriter(args.output_file)
    prefix_fuzzer = PrefixFuzzer(card=card, file_writer=file_writer, ins_start=args.start_ins, ins_end=args.end_ins, trust_mode=True)
    prefix_fuzzer.run()

if __name__ == "__main__":
    main()
