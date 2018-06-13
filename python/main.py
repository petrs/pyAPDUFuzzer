#!/usr/bin/env python3

import os
import logging
import time
import argparse


# 3rd party (PyScard)
from queue import Queue

from smartcard.System import readers

# LL Smartcard
from llsmartcard.card import SmartCard, CAC

from fuzzer.prefix_fuzzer import PrefixFuzzer
from objects import FuzzerInstruction
from utils.file_writer import FileWriter
from utils.util import auto_int
from utils.logging import init_logging, info


def get_card():
    reader_list = readers()
    if len(reader_list) > 1:
        print("Please select a reader")
        idx = 0
        for r in reader_list:
            print("  %d - %s"%(idx, r))
            idx += 1

        reader_idx = -1
        while reader_idx < 0 or reader_idx > len(reader_list)-1:
            reader_idx = int(input("Reader[%d-%d]: " % (0, len(reader_list)-1)))

        reader = reader_list[reader_idx]
    else:
        reader = reader_list[0]

    info("fuzzer","Using: %s" % reader)

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

    init_logging(logging.DEBUG)

    try:
        os.mkdir("result")
    except:
        pass

    card = get_card()
    file_writer = FileWriter(args.output_file)
    prefix_fuzzer = PrefixFuzzer(card=card, file_writer=file_writer, ins_start=args.start_ins, ins_end=args.end_ins, trust_mode=True, queue=Queue())

    valid_classes = prefix_fuzzer.get_classes()
    #valid_classes = [0x0B]

    for cla in valid_classes:
        header = [cla, 0x00, 0x00, 0x00, 0x00]
        mask = [(0, 0), (args.start_ins, args.end_ins), (0, 0), (0, 0), (0, 0)]
        fuzz_obj = FuzzerInstruction(header=header, mask=mask)
        prefix_fuzzer.add_testcase(fuzz_obj)

    prefix_fuzzer.run()


if __name__ == "__main__":
    main()
