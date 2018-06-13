from utils.card_interactor import CardInteractor
from queue import Queue, Empty
from objects import FuzzerObject
from const import ISO7816CODES, EXPERT_RULES

from utils.logging import info, warning

#
# FuzzerObject(cla=cla, bitmask=[0, 1, 1, 1, 0])
#


class PrefixFuzzer:
    def __init__(self, card, file_writer, ins_start, ins_end, trust_mode, queue=None):
        self.ins_start = ins_start
        self.ins_end = ins_end
        self.trust_mode = trust_mode
        self.file_writer = file_writer
        self.card_interactor = CardInteractor(card)
        self.queue = queue

    def run(self):
        info("fuzzer", "Brute forcing every command for each class...")
        self._process_queue()

        """
        for cla in valid_cla:
            for ins in range(self.ins_start,self.ins_end + 1):
                (sw1, sw2) = self.fuzz_instruction(cla, ins)

                if (sw1,sw2) ==  (0x6E,0x00):
                    invalid_class.append([cla, ins])

        for dat in invalid_class:
            for cla in range(0xFF + 1):
                if cla not in valid_cla:
                    self.fuzz_instruction(cla, dat[1])
        """
        info("fuzzer", "Done.")

    def get_classes(self):
        return self._enummerate_classes()

    def add_testcase(self, fuzzer_instruction):
        info("fuzzer", "Adding Fuzz Object {}".format(str(fuzzer_instruction)))
        self.queue.put(fuzzer_instruction)

    def _process_queue(self):
        while True:
            try:
                elem = self.queue.get(block=False)
            except Empty:
                break

            self._fuzz_element(elem)

    def _fuzz_element(self, elem):
        for cla in elem.get_test_elements(0):
            for ins in elem.get_test_elements(1):
                for p1 in elem.get_test_elements(2):
                    for p2 in elem.get_test_elements(3):
                        for num in elem.get_test_elements(4):
                            test_elem = FuzzerObject(cla, ins, p1, p2, num, [0]*num)
                            res = self.card_interactor.send_element(test_elem)
                            self._process_result(res)

    def _enummerate_classes(self):
        valid_cla = []

        info("fuzzer", "Enumerating valid classes...")
        for cla in range(0xFF + 1):
            apdu_to_send = [cla, 0x00, 0x00, 0x00]

            (sw1, sw2, data, timing) = self.card_interactor.send_apdu(apdu_to_send)

            # unsupported class is 0x6E00
            if (sw1 == 0x6E) and (sw2 == 0x00):
                continue
            else:
                valid_cla.append(cla)

        info("fuzzer", "Found %d valid command classes: " % len(valid_cla))
        if len(valid_cla) == 256:
            warning("fuzzer", "Class Checking seems to be disabled")
            valid_cla = [0x0B]
        else:
            for cla in valid_cla:
                print("%s" % hex(cla))
        return valid_cla

    def _process_result(self, element):
        self.file_writer.export_elem_as_json(element)
