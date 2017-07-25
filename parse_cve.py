#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Parse and extract spcecified CVE item from archived CVE-IDs.
"""
import os.path
import sys, re
import argparse
import csv
from logging import getLogger, StreamHandler, FileHandler, Formatter, DEBUG, INFO
import xml.etree.ElementTree as ET

__author__ = "Yuta OHURA <bultau@gmail.com>>"
__status__ = "development"
__version__ = "0.1"
__date__    = "23 June 2017"



if __name__ == '__main__':
    # pylint: disable=C0103
    logger = getLogger(__name__)
    handler = StreamHandler(sys.stdout)
    handler.setFormatter(Formatter('%(asctime)s %(message)s'))
    handler.setLevel(DEBUG)
    handler2 = FileHandler('out.log', 'w')
    handler2.setLevel(INFO)
    logger.setLevel(DEBUG)
    logger.addHandler(handler)
    logger.addHandler(handler2)

    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--list', help='the file path of the CVE ID list you want to extract', default='./data/list/')
    parser.add_argument('-b', '--base', help='the file path of the archived CVE ID', default='./data/base/allitems.xml')

    args = parser.parse_args()

    tree = ET.parse(args.base)
    root = tree.getroot()
    items = list()

    for root_dir, dirs, files in os.walk(args.list):
        print(root_dir)
        for file_ in files:
            full_path = os.path.join(root_dir, file_)
            print(full_path)
            out_file = 'output/' + '.'.join(os.path.basename(full_path).split('.')[:-1]) + '.csv'
            
            with open(full_path) as f:
                logger.debug(full_path + ' is processing...')
                for line in f:
                    if line == '':
                        next
                    cveid = line.strip()
                    item = root.find('.//*[@name=\'' + cveid + '\']')
                    logger.debug(item.attrib['name'] + ' is processing...')
                    tmp_item = dict()
                    tmp_item['cve-id'] = cveid
                    for elem in item:
                        tag = elem.tag.split('}')[1]
                        if tag == 'desc':
                            tmp_item[tag] = elem.text
                        elif tag == 'refs':
                            tmp_str = ''
                            for ref in elem:
                                tmp_attr = ref.attrib['source']
                                tmp_str += tmp_attr + ':' + ref.text + '\n'
                            tmp_item[tag] = tmp_str
                    items.append(tmp_item)

            with open(out_file, 'w', encoding='utf_8_sig') as f:
                writer = csv.writer(f, lineterminator='\n')

                for item in items:
                    line = [item['cve-id'], item['desc'], item['refs']]
                    writer.writerow(line)
