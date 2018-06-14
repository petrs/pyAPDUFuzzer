#!/usr/bin/env python3

import os
import sys
import logging
import time
import json
import time
import binascii
import argparse
import traceback
import psutil
import socket
from six.moves import input
from utils.card_interactor import CardInteractor

from config import CARD_READER_ID
from fuzzer.prefix_fuzzer import PrefixFuzzer
from objects import FuzzerObject
from utils.file_writer import FileWriter
from utils.util import auto_int, raise_critical_error
from utils.logging import init_logging, info, error


# logging.basicConfig(level=logging.DEBUG)

# 3rd party (PyScard)
# from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
#from smartcard.sw.SWExceptions import SWException

# LL Smartcard
# import llsmartcard.apdu as APDU
# from llsmartcard.apdu import APDU_STATUS, APPLET
from llsmartcard.card import SmartCard, CAC
import afl


INS_START = 0x00
INS_END = 0xFF
MODE_TRUST = True


TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 1024


try:
    # Python 3:
    stdin_compat = sys.stdin.buffer
except AttributeError:
    # There is no buffer attribute in Python 2:
    stdin_compat = sys.stdin


def llog(fd, msg):
    fd.write('%s:%s: %s\n' % (int(time.time() * 1000), psutil.Process().pid, msg))
    fd.flush()


def form_buffer(buffer):
    buffer = list(bytearray(buffer))
    ln = len(buffer)

    if ln < 4 or ln > 255:
        return None

    if ln > 4:
        buffer = buffer[0:4] + [ln - 4] + buffer[4:]
    return buffer


def server_fuzzer(fd, lfd):
    """
    Server fuzzer directly connected to the card.
    PCSC does not like forking which AFL does.
    Without forking the performance is very slow due to python reinit (7.8 rps).
    Over the TCP/IP channel we get 40-90 rps (card is the bottleneck now).

    :param fd:
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)
    llog(fd, 'Server mode...')

    card_interactor = CardInteractor(CARD_READER_ID)
    fwd = FileWriter(fd=lfd)

    llog(fd, 'reader: %s' % (card_interactor, ))

    while True:
        conn, addr = s.accept()
        llog(fd, 'conn: %s, addr: %s' % (conn, addr))

        while True:
            data = conn.recv(BUFFER_SIZE)
            if len(data) == 0:
                break

            data = data[1:]
            buffer = data
            if buffer is None:
                conn.send(bytes([0xff]))
                continue

            llog(fd, 'init4, buffer: %s' % binascii.hexlify(bytes(buffer)))

            # data, sw1, sw2, timing = send_apdu(card, buffer, fd)
            # data, sw1, sw2, timing = b'', 0, 0, b'0000'  # integration bechmark

            ln = int(buffer[4]) if len(buffer) >= 5 else 0
            test_elem = FuzzerObject(int(buffer[0]), int(buffer[1]), int(buffer[2]),
                                     int(buffer[3]), ln, list(bytearray(buffer[5:])))
            elem = card_interactor.send_element(test_elem)
            sw1 = test_elem.out['sw1']
            sw2 = test_elem.out['sw2']
            out = test_elem.out['data']

            statuscode = (sw1 << 8) + sw2
            time_bin = int(test_elem.misc['timing'] // 10)
            if time_bin < 0:
                time_bin = 0

            serialized_element = elem.serialize()
            fwd.print_to_file("%s" % json.dumps(serialized_element))

            llog(fd, 'status: %04x timing: %s' % (statuscode, time_bin))
            resp_data = bytes([0, sw1, sw2]) + bytes(time_bin.to_bytes(2, 'big')) + bytes(out)
            llog(fd, 'resp_data: %s' % binascii.hexlify(resp_data))

            conn.send(resp_data)

        conn.close()


def client_fuzzer(fd, lfd):
    """
    Client AFL fuzzer. Executed by AFL, fed to STDIN.
    Communicates with the fuzzer server, reads response, changes SHM.

    :param fd:
    :return:
    """
    global stdin_compat
    in_afl = os.getenv('PYTHON_AFL_PERSISTENT', None)

    llog(fd, 'init1')
    sys.settrace(None)
    llog(fd, 'init2, in afl: %s' % in_afl)

    # Call our fuzzer
    try:
        while afl.loop(3):
            sys.settrace(None)

            buffer = stdin_compat.read()
            buffer = form_buffer(buffer)
            if buffer is None:
                continue

            llog(fd, 'init4, buffer: %s' % binascii.hexlify(bytes(buffer)))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((TCP_IP, TCP_PORT))
            s.send(bytes([0]) + bytes(buffer))

            resp = s.recv(BUFFER_SIZE)
            llog(fd, 'Recv: %s' % binascii.hexlify(resp))
            if resp[0] != 0:
                llog(fd, 'Invalid response code: %s' % resp[0])
                continue

            sw1 = resp[1]
            sw2 = resp[2]
            timing = resp[3:5]
            data = resp[5:]
            statuscode = (sw1 << 8) + sw2

            llog(fd, 'status: %04x timing: %s' % (statuscode, timing))
            if in_afl:
                afl.trace_buff(bytes([sw1, sw2]))
                afl.trace_buff(bytes(data))
                afl.trace_buff(timing)

    except Exception as e:
        llog(fd, 'Exc: %s\n' % e)
        traceback.print_exc(file=fd)
        fd.flush()

    finally:
        fd.close()
        os._exit(0)


def prefix_fuzzing(fd):
    """
    Original forking fuzzer with AFL without TCP binding

    :param fd:
    :return:
    """

    global stdin_compat
    in_afl = os.getenv('PYTHON_AFL_PERSISTENT', None)

    # reader = get_reader()
    # card = connect_card(reader)

    llog(fd, 'init1')
    # afl.init()
    sys.settrace(None)
    llog(fd, 'init2, in afl: %s' % in_afl)

    # Call our fuzzer
    try:
        while afl.loop(3):
            sys.settrace(None)

            buffer = stdin_compat.read()
            buffer = form_buffer(buffer)
            if buffer is None:
                continue

            llog(fd, 'init4, buffer: %s' % binascii.hexlify(bytes(buffer)))
            reader = get_reader()
            card = connect_card(reader)

            data, sw1, sw2, timing = send_apdu(card, buffer, fd)
            statuscode = (sw1 << 8) + sw2
            time_bin = int(timing * 100)
            if time_bin < 0:
                time_bin = 0

            llog(fd, 'status: %04x timing: %s orig %s' % (statuscode, time_bin, timing))
            if in_afl:
                afl.trace_buff(bytes([sw1, sw2]))
                afl.trace_buff(bytes(data))
                afl.trace_buff(time_bin.to_bytes(2, 'big'))
            os._exit(0)

    except Exception as e:
        llog(fd, 'Exc: %s\n' % e)
        traceback.print_exc(file=fd)
        fd.flush()

    finally:
        fd.close()
        os._exit(0)


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
                        default="xdat.json",
                        help='File to output results to')
    parser.add_argument('--log', dest='log_file', action='store', type=str,
                        default="xres.json",
                        help='File to output log to')
    parser.add_argument('--server', dest='server', default=False, action='store_const', const=True,
                        help='Server mode')
    parser.add_argument('--client', dest='client', default=False, action='store_const', const=True,
                        help='client mode')

    args = parser.parse_args()
    INS_START = args.start_ins
    INS_END = args.end_ins
    INS_START = 0
    INS_END = 56
    try:
        os.mkdir("result")
    except:
        pass
    fd = open(args.log_file, "w")
    lfd = open(args.output_file, "w")

    llog(fd, 'init0')
    if args.server:
        server_fuzzer(fd, lfd)
    elif args.client:
        client_fuzzer(fd, lfd)
    else:
        prefix_fuzzing(fd)

    fd.close()
    lfd.close()


if __name__ == "__main__":
    main()
