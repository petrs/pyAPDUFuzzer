import logging
from smartcard.sw.SWExceptions import SWException
import time
import sys


class CardInteractor:
    def __init__(self, card):
        self.card = card

    def send_element(self, element):
        res = self.send_apdu(element.get_inp_data())
        element.set_output(res[0], res[1], res[2], res[3])
        return element

    def send_apdu(self, data):
        timing = -1
        stri = "Trying : ", [hex(i) for i in data]
        logging.debug(stri)
        try:

            start = time.time()
            (data, sw1, sw2) = self.card._send_apdu(data)
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

        stri = "Got : ", data, hex(sw1), hex(sw2)
        logging.debug(stri)

        return sw1, sw2, data, timing
