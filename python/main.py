#!/usr/bin/env python3
import sys
import os
import logging
import time
import argparse


# 3rd party (PyScard)
from queue import Queue

from config import CARD_READER_ID
from fuzzer.prefix_fuzzer import PrefixFuzzer
from objects import FuzzerInstruction, FuzzerObject
from utils.file_writer import FileWriter
from utils.util import auto_int, raise_critical_error
from utils.logging import init_logging, info, error




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


    file_writer = FileWriter(args.output_file)
    prefix_fuzzer = PrefixFuzzer(card_reader=CARD_READER_ID, file_writer=file_writer, ins_start=args.start_ins, ins_end=args.end_ins, trust_mode=args.trust_mode, queue=Queue())

    #valid_classes = prefix_fuzzer.get_classes()
    #valid_classes = [0x0B]
    valid_classes = []

    for cla in valid_classes:
        header = [cla, 0x00, 0x00, 0x00, 0x00]
        mask = [(0, 0), (args.start_ins, args.end_ins), (0, 0), (0, 0), (0, 0)]

        fuzz_obj = FuzzerInstruction(header=header, mask=mask)
        prefix_fuzzer.add_testcase(fuzz_obj)

    header = [0x0B, 0x14, 0x00, 0x00, 0x00]
    mask = [(0, 0),(0x14,0x15), (0, 0), (0, 0), (0, 0)]

    prefix_fuzzer.add_testcase(FuzzerInstruction(header=header, mask=mask))
    #prefix_fuzzer.add_testcase(FuzzerObject(cla=0x0B, ins=0x16, p1=0x01, p2=0x00, dlen=0x00, data=[]))
    prefix_fuzzer.run()


if __name__ == "__main__":
    main()
