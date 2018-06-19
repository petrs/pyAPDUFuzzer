import json

# {'in_cla': '0b', 'in_ins': '00', 'in_p1': '00', 'in_p2': '00', 'in_data': '', 'in_cmd': '0b00000000', 'out_status': '6d00', 'out_status_str': 'INS_NOT_SUPPORTED', 'out_data': '', 'timing': 18.4171199798584}
# {"inp": {"cla": "0x00", "ins": "0x00", "p1": "0x00", "p2": "0x00", "dlen": "0x00", "data": []},
# "out": {"sw1": "0x6d", "sw2": "0x00", "data": "", "status": "0x6d00", "status_str": "INS_NOT_SUPPORTED"}, "misc": {"timing": 4.443883895874023, "error_status": 0}}
out = open("out.json","w")
for line in open("../../result/overnight12062018.json").readlines():
    dat = json.loads(line)
    res = {'inp': {'cla': "0x{}".format(dat['in_cla']),
                   'ins': "0x{}".format(dat['in_ins']),
                   'p1': "0x{}".format(dat['in_p1']),
                   'p2': "0x{}".format(dat['in_p2']),
                   'dlen': "0x00",
                   'data': [],
                   },
           'out':{'sw1': "0x{}".format(dat['out_status'][0:2]),
                   'sw2':"0x{}".format(dat['out_status'][2:]),
                   'data': dat['out_data'],
                   'status': "0x{}".format(dat['out_status']),
                   'status_str': dat['out_status_str'],
                   },
           'misc':{
               'timing': dat['timing'],
                'error_status': 0
           }}
    out.write("{}\n".format(json.dumps(res)))
out.close()