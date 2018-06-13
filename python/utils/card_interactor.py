import logging

import smartcard
from smartcard.sw.SWExceptions import SWException
import time
import sys

from config import BLACKLIST
from utils.logging import debug, info, warning
from utils.util import raise_critical_error


class CardInteractor:
    def __init__(self, card):
        self.card = card

    def _is_blacklisted(self, element):
        for blcklst in BLACKLIST:
            ok = False
            for key in blcklst:
                if element.inp[key] not in blcklst[key]:
                    ok = True
            if not ok:
                warning('fuzzer', 'Hit a blacklisted paket {}'.format(element.get_inp_data()))
                return True

        return False

    def send_element(self, element):
        if self._is_blacklisted(element):
            element.misc['error_status'] = 1
            return element

        res = self.send_apdu(element.get_inp_data())
        element.set_output(res[0], res[1], res[2], res[3])
        return element

    def send_apdu(self, data):
        timing = -1
        stri = "Trying : ", [hex(i) for i in data]
        debug("card.interactor", stri)
        try:
            start = time.time()
            (data, sw1, sw2) = self.card._send_apdu(data)
            end = time.time()
            timing = end - start

        except SWException as e:
            # Did we get an unsuccessful attempt?
            info("card.interactor",e)
        except KeyboardInterrupt:
            sys.exit()
        except smartcard.Exceptions.CardConnectionException as ex:
            raise_critical_error("card.interactor", ex)
        except Exception as e:
            warning("card.interactor","{}:{}".format(type(e), e))
            (data, sw1, sw2) = ([], 0xFF, 0xFF)

        stri = "Got : ", data, hex(sw1), hex(sw2)
        debug("card.interactor", stri)

        return sw1, sw2, data, timing
