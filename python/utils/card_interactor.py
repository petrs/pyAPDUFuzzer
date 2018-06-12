import logging
from smartcard.sw.SWExceptions import SWException
import time
import sys

class CardInteractor:
    def __init__(self, card):
        self.card = card

    def send_apdu(self, data):
        timing = -1
        str = "Trying : ", [hex(i) for i in data]
        logging.debug(str)
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

        str = "Got : ", data, hex(sw1), hex(sw2)
        logging.debug(str)

        return (data, sw1, sw2, timing)
