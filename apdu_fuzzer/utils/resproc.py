import json
import collections
from functools import reduce


def load_json(fname=None, fd=None, data=None):
    if fname and not data:
        fd = open(fname)
    try:
        res = []
        data = data if data else fd.read()
        data = remove_null_prefix(data)

        lines = data.split('\n')
        for line in lines:
            line = line.strip()
            if line == '':
                continue
            js = json.loads(line, object_pairs_hook=collections.OrderedDict)
            res.append(js)

        return res

    finally:
        if fname and not data:
            fd.close()


def remove_null_prefix(data):
    for i, x in enumerate(data):
        if x != '\x00':
            data = data[i:]
            break
    return data


def uniq(iterable, key=lambda x: x):
    """
    Remove duplicates from an iterable. Preserves order.
    :type iterable: Iterable[Ord => A]
    :param iterable: an iterable of objects of any orderable type
    :type key: Callable[A] -> (Ord => B)
    :param key: optional argument; by default an item (A) is discarded
    if another item (B), such that A == B, has already been encountered and taken.
    If you provide a key, this condition changes to key(A) == key(B); the callable
    must return orderable objects.
    """
    keys = set()
    res = []
    for x in iterable:
        k = key(x)
        if k in keys:
            continue

        res.append(x)
        keys.add(k)
    return res

    # Enumerate the list to restore order lately; reduce the sorted list; restore order
    # def append_unique(acc, item):
    #     return acc if key(acc[-1][1]) == key(item[1]) else acc.append(item) or acc
    # srt_enum = sorted(enumerate(iterable), key=lambda item: key(item[1]))
    # return [item[1] for item in sorted(reduce(append_unique, srt_enum, [srt_enum[0]]))]


def merge_dicts(dicts):
    dres = collections.OrderedDict()
    for dc in dicts:
        dres.update(dc)
    return dres



