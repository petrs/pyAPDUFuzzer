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
from pyhashxx import hashxx

from .utils.card_interactor import CardInteractor
from .config import CARD_READER_ID
from .fuzzer.prefix_fuzzer import PrefixFuzzer
from .objects import FuzzerObject
from .utils.file_writer import FileWriter
from .utils.util import auto_int, raise_critical_error
from .utils.logging import init_logging, info, error


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


FD = None
SOCK_IP = '127.0.0.1'
SOCK_PORT = 5005
SOCK_TYPE = socket.SOCK_DGRAM  # SOCK_STREAM
BUFFER_SIZE = 1024


class SockComm(object):
    def __init__(self, server=True):
        self.server = server
        self.s = None
        self.conn = None
        self.addr = None

    def start(self):
        self.s = socket.socket(socket.AF_INET, SOCK_TYPE)
        self.s.bind((SOCK_IP, SOCK_PORT))

        if SOCK_TYPE == socket.SOCK_STREAM:
            self.s.listen(1)

    def connect(self):
        if SOCK_TYPE == socket.SOCK_STREAM:
            self.s = socket.socket(socket.AF_INET, SOCK_TYPE)
            self.s.connect((SOCK_IP, SOCK_PORT))
        else:
            self.s = socket.socket(socket.AF_INET, SOCK_TYPE)
            self.addr = (SOCK_IP, SOCK_PORT)

    def accept(self):
        if SOCK_TYPE == socket.SOCK_STREAM:
            self.conn, self.addr = self.s.accept()
        else:
            return

    def read(self):
        if SOCK_TYPE == socket.SOCK_STREAM:
            return self.conn.recv(BUFFER_SIZE)
        else:
            data, self.addr = self.s.recvfrom(BUFFER_SIZE)
            return data

    def send(self, buff):
        if SOCK_TYPE == socket.SOCK_STREAM:
            return self.conn.send(buff)
        else:
            return self.s.sendto(buff, self.addr)

    def close(self):
        if SOCK_TYPE == socket.SOCK_STREAM:
            self.s.close()

    def close_conn(self):
        if SOCK_TYPE == socket.SOCK_STREAM:
            if self.conn:
                self.conn.close()

    def __repr__(self):
        return '<Socket type:%s, s:%s, conn:%s, addr:%s>' % (SOCK_TYPE, self.s, self.conn, self.addr)


try:
    # Python 3:
    stdin_compat = sys.stdin.buffer
except AttributeError:
    # There is no buffer attribute in Python 2:
    stdin_compat = sys.stdin


def llog(fd=None, msg=None):
    if fd is None:
        fd = FD
    fd.write('%s:%s: %s\n' % (int(time.time() * 1000), psutil.Process().pid, msg))
    fd.flush()


def gen_input(len=4):
    with open('inputs/zeros_%04d.bin' % len, 'wb') as fh:
        fh.write(bytes([0]*len))


def purge_inputs():
    folder = 'inputs'
    for the_file in os.listdir(folder):
        file_path = os.path.join(folder, the_file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            # elif os.path.isdir(file_path): shutil.rmtree(file_path)
        except Exception as e:
            print(e)


def form_buffer(buffer):
    buffer = list(bytearray(buffer))
    ln = len(buffer)

    if ln < 4 or ln > 255:
        return None

    if ln > 4:
        buffer = buffer[0:4] + [ln - 4] + buffer[4:]
    return buffer


def server_fuzzer(fd, lfd, args=None, **kwargs):
    """
    Server fuzzer directly connected to the card.
    PCSC does not like forking which AFL does.
    Without forking the performance is very slow due to python reinit (7.8 rps).
    Over the TCP/IP channel we get 40-90 rps (card is the bottleneck now).

    :param fd:
    :param lfd:
    :param args:
    :return:
    """
    s = SockComm()
    s.start()

    llog(fd, 'Server mode...')

    if not args.dry:
        card_interactor = CardInteractor(CARD_READER_ID)
        llog(fd, 'reader: %s' % (card_interactor,))

    fwd = FileWriter(fd=lfd)
    while True:
        s.accept()
        llog(fd, 'conn: %s' % s)

        try:
            while True:
                data = s.read()
                if len(data) == 0:
                    break

                data = data[1:]
                buffer = data
                if buffer is None:
                    s.send(bytes([0xff]))
                    continue

                llog(fd, 'init4, buffer: %s' % binascii.hexlify(bytes(buffer)))

                # data, sw1, sw2, timing = send_apdu(card, buffer, fd)
                # data, sw1, sw2, timing = b'', 0, 0, b'0000'  # integration bechmark

                ln = int(buffer[4]) if len(buffer) >= 5 else 0
                test_elem = FuzzerObject(int(buffer[0]), int(buffer[1]), int(buffer[2]),
                                         int(buffer[3]), ln, list(bytearray(buffer[5:])))
                elem = test_elem
                if args.dry:
                    elem = test_elem
                    sw1 = 0
                    sw2 = 0
                    out = bytes()
                else:
                    elem = card_interactor.send_element(test_elem)
                    sw1 = elem.out['sw1']
                    sw2 = elem.out['sw2']
                    out = elem.out['data']

                statuscode = (sw1 << 8) + sw2
                time_bin = int(test_elem.misc['timing'] // 10)
                if time_bin < 0:
                    time_bin = 0

                serialized_element = elem.serialize()
                fwd.print_to_file("%s" % json.dumps(serialized_element))

                llog(fd, 'status: %04x timing: %s' % (statuscode, time_bin))
                resp_data = bytes([0, sw1, sw2]) + bytes(time_bin.to_bytes(2, 'big')) + bytes(out)
                llog(fd, 'resp_data: %s' % binascii.hexlify(resp_data))

                s.send(resp_data)

        except KeyboardInterrupt:
            break

        s.close_conn()


class Templater(object):
    def __init__(self, args):
        self.inp_len = args.fix_len
        self.sample_len = self.inp_len
        self.inp_len_b = self.inp_len or 0
        self.inp_len_s = self.inp_len or 0
        self.gen_h_len = None
        self.tpl_b = None
        self.mask_b = None

        if args.tpl:
            self.tpl_b = binascii.unhexlify(args.tpl)
            self.mask_b = binascii.unhexlify(args.mask)
            if len(self.tpl_b) != len(self.mask_b):
                raise ValueError('Invalid mask / tpl')

            self.gen_h_len = sum([1 for i, x in enumerate(self.mask_b) if x > 0 and i < 4])
            self.inp_len = sum([1 for x in self.mask_b if x > 0])  # FF00 = generate first byte randomly, second is fix from the tpl
            self.sample_len = self.inp_len

            if args.fix_len_b:
                self.sample_len = args.fix_len_b + self.gen_h_len
                self.inp_len_b = args.fix_len_b
                self.inp_len_s = args.fix_len_s
            else:
                self.inp_len_b = self.sample_len - self.gen_h_len
                self.inp_len_s = self.sample_len - self.gen_h_len

            if args.fix_len:
                raise ValueError('Fix len is auto-determined from the mask')

    def gen_inputs(self):
        purge_inputs()
        if self.inp_len_b == self.inp_len_s:
            gen_input(self.sample_len)  # 4-bytes by default
        else:
            for i in range(self.inp_len_b, self.inp_len_s + 1):
                gen_input(self.gen_h_len + i)  # 4-bytes by default

    def transform(self, fuzz):
        ln = len(fuzz)

        # Length check
        if self.inp_len_b:
            if ln - self.gen_h_len > self.inp_len_s:
                return None
            if ln - self.gen_h_len < self.inp_len_b:
                return None
        elif self.inp_len:
            if ln - self.gen_h_len != self.inp_len:
                return None

        # Payload building from mask & template if applicable
        if self.tpl_b:
            res = []
            c = 0
            mask_len = len(self.mask_b)
            rng = 5 + min(ln - self.gen_h_len, self.inp_len_s)
            if rng == 5:
                rng = 4

            for i in range(rng):
                if i == 4:  # length
                    res.append(ln - self.gen_h_len)  # payload length = fuzz buffer - fuzzed header fields
                elif i >= mask_len or self.mask_b[i]:  # randomly if mask is too short or specified by the mask to be random
                    res.append(fuzz[c])
                    c += 1
                else:
                    res.append(self.tpl_b[i])  # should exist in template

            return bytearray(res)

        # Simple payload gen, length fixing
        return form_buffer(fuzz)

    def __repr__(self):
        return '<Templater: %s>' % self.__dict__


def client_fuzzer(fd, lfd, args=None, **kwargs):
    """
    Client AFL fuzzer. Executed by AFL, fed to STDIN.
    Communicates with the fuzzer server, reads response, changes SHM.

    :param fd:
    :param lfd:
    :param args:
    :return:
    """
    global stdin_compat
    in_afl = os.getenv('PYTHON_AFL_PERSISTENT', None)

    llog(fd, 'init1')
    sys.settrace(None)
    llog(fd, 'init2, in afl: %s' % in_afl)

    # Argument processing
    tpler = Templater(args)
    llog(fd, 'templater: %s' % tpler)

    # by default, start with 4byte input - fuzz instruction with empty data
    tpler.gen_inputs()

    # Call our fuzzer
    try:
        # s = csock()  # Pre-fork connection. needs more sophisticated reconnect if socket is broken.
        while afl.loop(3):
            sys.settrace(None)
            buffer = stdin_compat.read()
            buffer = tpler.transform(buffer)
            if buffer is None:
                continue

            llog(fd, 'init4, buffer: %s' % binascii.hexlify(bytes(buffer)))

            s = SockComm(server=False)
            s.connect()
            s.send(bytes([0]) + bytes(buffer))

            resp = s.read()
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
                afl.trace_offset(hashxx(bytes([sw1, sw2])))
                afl.trace_offset(hashxx(timing))
                afl.trace_offset(hashxx(bytes(data)))

    except Exception as e:
        llog(fd, 'Exc: %s\n' % e)
        traceback.print_exc(file=fd)
        fd.flush()

    except KeyboardInterrupt:
        return

    finally:
        fd.close()
        os._exit(0)


def prefix_fuzzing(fd, lfd, args=None, **kwargs):
    """
    Original forking fuzzer with AFL without TCP binding

    :param fd:
    :param args:
    :return:
    """

    global stdin_compat
    in_afl = os.getenv('PYTHON_AFL_PERSISTENT', None)

    # reader = get_reader()
    # card = connect_card(reader)

    llog(fd, 'init1')
    fwd = FileWriter(fd=lfd)
    sys.settrace(None)
    llog(fd, 'init2, in afl: %s' % in_afl)

    # Call our fuzzer
    try:
        while afl.loop(3):  # afl.init()
            sys.settrace(None)

            buffer = stdin_compat.read()
            buffer = form_buffer(buffer)
            if buffer is None:
                continue

            llog(fd, 'init4, buffer: %s' % binascii.hexlify(bytes(buffer)))
            ln = int(buffer[4]) if len(buffer) >= 5 else 0
            test_elem = FuzzerObject(int(buffer[0]), int(buffer[1]), int(buffer[2]),
                                     int(buffer[3]), ln, list(bytearray(buffer[5:])))

            if args.dry:
                elem = test_elem
                sw1 = 0
                sw2 = 0
                out = bytes()

            else:
                card_interactor = CardInteractor(CARD_READER_ID)
                llog(fd, 'reader: %s' % (card_interactor,))

                elem = card_interactor.send_element(test_elem)
                sw1 = elem.out['sw1']
                sw2 = elem.out['sw2']
                out = elem.out['data']

            statuscode = (sw1 << 8) + sw2
            time_bin = int(test_elem.misc['timing'] // 10)
            if time_bin < 0:
                time_bin = 0

            serialized_element = elem.serialize()
            fwd.print_to_file("%s" % json.dumps(serialized_element))

            llog(fd, 'status: %04x timing: %s' % (statuscode, time_bin))
            if in_afl:
                afl.trace_buff(bytes([sw1, sw2]))
                afl.trace_buff(bytes(out))
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
    global INS_START, INS_END, FD
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
    parser.add_argument('--dry', dest='dry', default=False, action='store_const', const=True,
                        help='dry run - no card comm')

    parser.add_argument('--payload-len', dest='fix_len', default=None, type=int,
                        help='Fixed length of the payload in bytes')
    parser.add_argument('--payload-len-b', dest='fix_len_b', default=None, type=int,
                        help='Payload length start')
    parser.add_argument('--payload-len-s', dest='fix_len_s', default=None, type=int,
                        help='Payload length stop')

    parser.add_argument('--tpl', default=None,
                        help='Template for the message. First 4 bytes are the header.')
    parser.add_argument('--mask', default=None,
                        help='Mask for the template')

    args = parser.parse_args()
    INS_START = args.start_ins
    INS_END = args.end_ins
    INS_START = 0
    INS_END = 56
    try:
        os.mkdir("result")
    except:
        pass

    FD = fd = open(args.log_file, "w")
    lfd = open(args.output_file, "w")

    llog(fd, 'init0')
    if args.server:
        server_fuzzer(fd, lfd, args)
    elif args.client:
        client_fuzzer(fd, lfd, args)
    else:
        prefix_fuzzing(fd, lfd, args)

    fd.close()
    lfd.close()


if __name__ == "__main__":
    main()
