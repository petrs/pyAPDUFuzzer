#!/usr/bin/env python

import argparse
import json
import sys

from elasticsearch import Elasticsearch, helpers

parser = argparse.ArgumentParser(description='Import Results')
parser.add_argument('--id', dest='id', action='store', help='Card Identifier', required=True)
parser.add_argument('--in', dest='in_file', action='store', help='Input file', required=True)
parser.add_argument('--ignore-existing', dest='ignore_existing', action='store_true', default=False,
                    help='Overwrite indices')
parser.add_argument('--delete-index', dest='delete_index', action='store_true', default=False,
                    help='Deletes indices before insertion')
args = parser.parse_args()

data_set = []
i = 0

try:
    password = open(".password", "r").read().strip()
except:
    print("Please place the password in this folder in a file called .password")
    sys.exit(1)

client = Elasticsearch(
    'apdues.dray.wtf',
    http_auth=('admin', password),
    scheme="https",
    port=443,
)


def send_data():
    global data_set
    helpers.bulk(client, data_set, index=args.id, doc_type='result', refresh=True)
    data_set = []


def process_data(dat):
    global data_set, i
    dat = prepare_data(dat)
    data_set.append({
        "_index": args.id,
        "_type": 'result',
        "_source": dat
    })
    i += 1
    if i % 100000 == 0:
        print(i)
        send_data()


def prepare_data(data):
    data['inp']['cla'] = int(data['inp']['cla'], 16)
    data['inp']['ins'] = int(data['inp']['ins'], 16)
    data['inp']['p1'] = int(data['inp']['p1'], 16)
    data['inp']['p2'] = int(data['inp']['p2'], 16)
    data['inp']['dlen'] = int(data['inp']['dlen'], 16)

    data['out']['sw1'] = int(data['out']['sw1'], 16)
    data['out']['sw2'] = int(data['out']['sw2'], 16)
    data['out']['status'] = int(data['out']['status'], 16)
    return data


if args.delete_index:
    client.indices.delete(index=args.id, ignore=[400, 404])
try:
    client.indices.create(index=args.id, ignore=400)
except Exception as e:
    if not args.ignore_existing:
        print("Error: {}".format(e))
        sys.exit(1)

try:
    data = json.load(open(args.in_file))
    for dat in data:
        process_data(dat)
except ValueError:
    print("Unable to parse real json file. Trying line by line")
    for line in open(args.in_file).readlines():
        process_data(json.loads(line))

send_data()
print("Finished uploading {} elements".format(i))
