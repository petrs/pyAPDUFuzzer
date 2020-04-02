#!/usr/bin/env python3
import json
import sys

APDU_HEADER = ["cla", "ins", "p1", "p2", "dlen"]
POWER_OF_256 = list(256 ** p for p in range(0, 5))


def get_step(prev_data, data):
    """
    Returns difference between two following APDUs. (step)
    If APDU's are not in the same sequence (step is not a power of 256)
    or response APDU's are not the same, then it returns None.
    """
    apdu_value = apdu_to_int(data["inp"])
    step = apdu_value - get_step.prev_apdu_value
    get_step.prev_apdu_value = apdu_value

    if (data["out"]["status"] == prev_data["out"]["status"]) and (step in POWER_OF_256):
        return step
    else:
        return None


def apdu_to_int(apdu):
    """
    Returns the integer representation of APDU's header.
    """
    value = 0
    for i, field in enumerate(list(apdu.values())[:-1]):
        value *= 256
        value += int(field, 16)
    return value


def get_count(start, end, step):
    """
    Returns the number of ADPUs in sequence.
    """
    if step is None:
        return 1
    else:
        return ((apdu_to_int(end["inp"]) - apdu_to_int(start["inp"])) // step) + 1


def print_data(start, end, step, count):
    """
    Prints information about the sequence of related APDUs.
    """
    del start["inp"]["data"]
    if count == 1:
        print('{{"inp": {}, "status": {}, "status_str": {}}}'
              .format(json.dumps(start["inp"]),
                      json.dumps(start["out"]["status"]),
                      json.dumps(start["out"]["status_str"])))
    else:
        step = APDU_HEADER[-POWER_OF_256.index(step) - 1]
        changed = False
        for key in start["inp"]:
            if start["inp"][key] != end["inp"][key]:
                changed = True
            if changed:
                start["inp"][key] += '->' + end["inp"][key]
            if key == step:
                break
        print('{{"inp": {}, "count": {}, "status": {}, "status_str": {}}}'
              .format(json.dumps(start["inp"]),
                      json.dumps(count),
                      json.dumps(start["out"]["status"]),
                      json.dumps(start["out"]["status_str"])))


def main():
    prev_data = json.loads(sys.stdin.readline())  # input from previous iteration
    get_step.prev_apdu_value = apdu_to_int(prev_data["inp"])  # optimization
    seq_start = prev_data  # start of APDU sequence
    prev_step = None  # difference between previous APDUs
    #total_count = 0  # total number of processed ADPUs

    # We iterate here over all APDUs on input.
    # If we found an increasing sequence of APDUs with
    # the same step between them, we print them after we
    # find APDU, which is not belonging to the sequence.
    for data in (json.loads(line) for line in sys.stdin):
        step = get_step(prev_data, data)
        if (step != prev_step and prev_step is not None) or (step is None):
            count = get_count(seq_start, prev_data, prev_step)
            print_data(seq_start, prev_data, prev_step, count)
            #total_count += count
            seq_start = data
        prev_data = data
        prev_step = step

    # We need to print remaining data.
    count = get_count(seq_start, prev_data, prev_step)
    print_data(seq_start, prev_data, prev_step, count)
    #total_count += count
    #print("Total count: {:,}".format(total_count))


if __name__ == "__main__":
    main()
