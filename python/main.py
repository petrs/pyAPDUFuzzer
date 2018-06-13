#!/usr/bin/env python3
import sys
import os
import logging
import time
import argparse


# 3rd party (PyScard)
from queue import Queue

import smartcard
from smartcard.System import readers

# LL Smartcard
from llsmartcard.card import CAC


from fuzzer.prefix_fuzzer import PrefixFuzzer
from objects import FuzzerInstruction, FuzzerObject
from utils.file_writer import FileWriter
from utils.util import auto_int, raise_critical_error
from utils.logging import init_logging, info, error


def get_card():
    reader_list = readers()
    if not len(reader_list):
        error("fuzzer", "No Reader found")
        sys.exit(1)
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
    try:
        connection = reader.createConnection()
        connection.connect()

        card = CAC(connection)
    except smartcard.Exceptions.NoCardException as ex:
        raise_critical_error("card.interactor", ex)

    return card


def main():
    parser = argparse.ArgumentParser(description='Fuzz smartcard api.')
    parser.add_argument('--start_ins', dest='start_ins', action='store', type=auto_int,
                        default=0x00, help='Instruction to start fuzzing at')
    parser.add_argument('--end_ins', dest='end_ins', action='store', type=auto_int,
                        default=0xff, help='Instruction to stop fuzzing at')
    parser.add_argument('--output', dest='output_file', action='store', type=str,
                        default="result/{}-export.json".format(str(time.time()).replace(".","")), help='File to output results to')
    parser.add_argument('--no-trust', dest='trust_mode', action='store_false', default=True)
    args = parser.parse_args()

    init_logging(logging.DEBUG)

    try:
        os.mkdir("result")
    except:
        pass

    card = get_card()
    file_writer = FileWriter(args.output_file)
    prefix_fuzzer = PrefixFuzzer(card=card, file_writer=file_writer, ins_start=args.start_ins, ins_end=args.end_ins, trust_mode=args.trust_mode, queue=Queue())

    #valid_classes = prefix_fuzzer.get_classes()
    #valid_classes = [0x0B]
    valid_classes = []

    for cla in valid_classes:
        header = [cla, 0x00, 0x00, 0x00, 0x00]
        mask = [(0, 0), (args.start_ins, args.end_ins), (0, 0), (0, 0), (0, 0)]

        fuzz_obj = FuzzerInstruction(header=header, mask=mask)
        prefix_fuzzer.add_testcase(fuzz_obj)


    header = [0x0B, 0x14, 0x00, 0x00, 0x00]
    mask = [(0, 0),(0,0), (0x33, 0xFF), (0, 0x05), (0, 0)]

    prefix_fuzzer.add_testcase(FuzzerInstruction(header=header, mask=mask))
    #prefix_fuzzer.add_testcase(FuzzerObject(cla=0x0B, ins=0x16, p1=0x01, p2=0x00, dlen=0x00, data=[]))
    prefix_fuzzer.run()


if __name__ == "__main__":
    main()
