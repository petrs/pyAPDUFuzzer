import smartcard
from llsmartcard.card import CAC
from smartcard.System import readers
from smartcard.sw.SWExceptions import SWException
import time
import sys

from config import BLACKLIST
from utils.logging import debug, info, warning, error
from utils.util import raise_critical_error


class CardCrashedException(Exception):
    pass


class CardInteractor:

    def __init__(self, card_reader_id):
        self.card_reader_id = card_reader_id
        self.card_connection = None
        self.card = self.get_card()

    def get_card(self):
        if self.card_connection:
            self.card_connection.disconnect()
        reader_list = readers()
        card_reader = reader_list[self.card_reader_id]

        try:
            connection = card_reader.createConnection()
            self.card_connection = connection
            connection.connect()
            return CAC(connection)

        except smartcard.Exceptions.NoCardException as ex:
            raise_critical_error("card.interactor", ex)

    @staticmethod
    def _is_blacklisted(element):
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
        try:
            res = self.send_apdu(element.get_inp_data())
            element.set_output(res[0], res[1], res[2], res[3])
        except CardCrashedException:
            element.misc['error_status'] = 1
        return element

    # noinspection PyProtectedMember
    def send_apdu(self, data):
        timing = -1
        sw1 = 0x00
        sw2 = 0x00
        stri = "Trying : ", [hex(i) for i in data]
        debug("card.interactor", stri)
        try:

            start = time.time()
            (data, sw1, sw2) = self.card._send_apdu(data)
            end = time.time()
            timing = end - start
        except SWException as e:
            # Did we get an unsuccessful attempt?
            info("card.interactor", e)
        except KeyboardInterrupt:
            sys.exit()
        except smartcard.Exceptions.CardConnectionException as ex:
            warning("card.interactor", "Reconnecting the card because of {} while processing {}".format(ex, str(data)))
            self.card = self.get_card()
            raise CardCrashedException
        except Exception as e:
            warning("card.interactor", "{}:{}".format(type(e), e))
            (data, sw1, sw2) = ([], 0xFF, 0xFF)

        stri = "Got : ", data, hex(sw1), hex(sw2)
        debug("card.interactor", stri)

        return sw1, sw2, data, timing
