from utils.card_interactor import CardInteractor

from const import ISO7816CODES
import time

class PrefixFuzzer:
    def __init__(self, card, file_writer, ins_start, ins_end, trust_mode, queue=None):
        self.ins_start = ins_start
        self.ins_end = ins_end
        self.trust_mode = trust_mode
        self.file_writer = file_writer
        self.card_interactor = CardInteractor(card)
        self.queue = queue
        
    def run(self):
        valid_cla = []

        print("Enumerating valid classes...")
        for cla in range(0xFF + 1):
            apdu_to_send = [cla, 0x00, 0x00, 0x00]

            (data, sw1, sw2, timing) = self.card_interactor.send_apdu(apdu_to_send)

            # unsupported class is 0x6E00
            if (sw1 == 0x6E) and (sw2 == 0x00):
                continue
            else:
                valid_cla.append(cla)

        print("Found %d valid command classes: " % len(valid_cla))
        if len(valid_cla) == 256:
            print("Class Checking seems to be disabled")
            valid_cla = [0x0B]
        else:
            for cla in valid_cla:
                print("%s" % hex(cla))

        print("Brute forcing every command for each class...")
        invalid_class = []
        for cla in valid_cla:
            for ins in range(self.ins_start,self.ins_end + 1):
                (sw1, sw2) = self.fuzz_instruction(cla, ins)

                if (sw1,sw2) ==  (0x6E,0x00):
                    invalid_class.append([cla, ins])


        for dat in invalid_class:
            for cla in range(0xFF + 1):
                if cla not in valid_cla:
                    self.fuzz_instruction(cla, dat[1])

        print("Done.")

    def fuzz_instruction(self, cla, ins):
        for p1 in range(0xFF + 1):
            for p2 in range(0xFF + 1):
                apdu_to_send = [cla, ins, p1, p2]
                (data, sw1, sw2, timing) = self.card_interactor.send_apdu(apdu_to_send)
                self.file_writer.export_json(cla, ins, p1, p2, 0,"",sw1, sw2, data, timing)
                if (sw1,sw2) ==  (0x6E,0x00):
                    return (sw1,sw2)

                if (sw1,sw2) ==  (0x6D,0x00) and self.trust_mode:
                    return (sw1,sw2)
        return (0,0)
