import copy

from utils.const import ISO7816CODES


class FuzzerInstruction:

    def __init__(self, header=None, data=None, mask=None, follow_expert_rules=True, expert_rules=None):
        if expert_rules is None:
            expert_rules = []
        if data is None:
            data = []
        if mask is None:
            mask = [(0, 0), (0, 0), (0, 0), (0, 0), (0, 0)]
        if header is None:
            header = [0x00, 0x00, 0x00, 0x00, 0x00]
        self.header = header
        self.data = data
        self.mask = mask
        self.num_of_tries = 1

        for a in mask:
            if (a[1]-a[0]) > 0:
                self.num_of_tries *= a[1]-a[0]

        self.expert_rules = expert_rules
        self.follow_expert_rules = follow_expert_rules

    def get_test_elements(self, pos):
        elem_mask = self.mask[pos]

        if elem_mask == (0, 0):
            return [self.header[pos]]
        else:
            return list(range(elem_mask[0], elem_mask[1] + 1))

    def get_follow_expert_rules(self):
        return self.follow_expert_rules

    def __str__(self):
        return "Instruction H: {} M: {} D: {}".format(str(self.header), str(self.mask), str(self.data))


class FuzzerObject:

    def __init__(self, cla=0x00, ins=0x00, p1=0x00, p2=0x00, dlen=0x00, data=None, follow_expert_rules=True):
        if data is None:
            data = []
        self.inp = {}
        self.out = {}
        self.misc = {}

        self.inp['cla'] = cla
        self.inp['ins'] = ins
        self.inp['p1'] = p1
        self.inp['p2'] = p2
        self.inp['dlen'] = dlen
        self.inp['data'] = data

        self.out['sw1'] = 0x00
        self.out['sw2'] = 0x00
        self.out['data'] = []

        self.misc['timing'] = 0
        self.misc['error_status'] = 0

        self.follow_expert_rules = follow_expert_rules

    def set_input(self, cla, ins, p1, p2, dlen=0, data=None):
        if data is None:
            data = []
        self.inp['cla'] = cla
        self.inp['ins'] = ins
        self.inp['p1'] = p1
        self.inp['p2'] = p2
        self.inp['dlen'] = dlen
        self.inp['data'] = data

    def set_output(self, sw1, sw2, data, timing):
        self.out['sw1'] = sw1
        self.out['sw2'] = sw2
        self.out['data'] = data
        self.misc['timing'] = timing * 1000

    def get_inp_data(self):
        return [self.inp['cla'], self.inp['ins'], self.inp['p1'], self.inp['p2'], self.inp['dlen']] + self.inp['data']

    def get_status_code(self):
        return (self.out['sw1'] << 8) + self.out['sw2']

    def __str__(self):
        return str(
            [self.inp['cla'], self.inp['ins'], self.inp['p1'], self.inp['p2'], self.inp['dlen']] + self.inp['data'])

    def serialize(self):
        ret = {"inp": copy.deepcopy(self.inp), "out": copy.deepcopy(self.out), "misc": copy.deepcopy(self.misc)}

        status_code = self.get_status_code()

        try:
            out_status_str = ISO7816CODES[status_code]
        except KeyError:
            out_status_str = "UNKNOWN"

        ret["out"]['status'] = "0x{:04x}".format(status_code)
        ret["out"]['status_str'] = out_status_str
        ret["out"]['data'] = ("0x" if len(ret["out"]['data']) > 0 else "") + "".join(
            ["{:02x}".format(d) for d in ret["out"]['data']])

        ret["inp"] = self._convert_numbers_to_hex(ret["inp"])
        ret["out"] = self._convert_numbers_to_hex(ret["out"])
        return ret

    @staticmethod
    def _convert_numbers_to_hex(arr):
        for el in arr:
            if isinstance(arr[el], int):
                arr[el] = "0x{:02x}".format(arr[el])
        return arr

    def to_array(self):
        return {
            "inp": self.inp,
            "out": self.out,
            "misc": self.misc
        }
