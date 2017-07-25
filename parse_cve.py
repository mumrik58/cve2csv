#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Create CSV from archived CVE list(allitems.xml) and arbitrary CVE list.
"""
import os.path
import sys
import urllib.request
import gzip
import argparse
import csv
from logging import getLogger, StreamHandler, FileHandler, Formatter, DEBUG, INFO
import xml.etree.ElementTree as ET

__author__ = 'Yuta OHURA <bultau@gmail.com>'
__status__ = 'development'
__version__ = '0.1'
__date__ = '23 June 2017'

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
    parser.add_argument('-b', '--base', help='the file path of the archived CVE ID', default='')

    args = parser.parse_args()

    base_path = ''
    if args.base == '':
        logger.info('There is no allitems.xml, getting the latest one...')
        url = 'http://cve.mitre.org/data/downloads/allitems.xml.gz'
        urllib.request.urlretrieve(url, './data/base/allitems.xml.gz')
        with gzip.open('./data/base/allitems.xml.gz', 'rb') as f_in:
            with open('./data/base/allitems.xml', 'wb') as f_out:
                f_out.write(f_in.read())
        base_path = './data/base/allitems.xml'
    else:
        base_path = args.base
    tree = ET.parse(base_path)
    root = tree.getroot()
    items = list()

    for root_dir, dirs, files in os.walk(args.list):
        print(root_dir)
        for file_ in files:
            full_path = os.path.join(root_dir, file_)
            print(full_path)
            out_file = 'output/' + '.'.join(os.path.basename(full_path).split('.')[:-1]) + '.csv'

            with open(full_path) as f_in:
                with open(out_file, 'w', encoding='utf_8_sig') as f_out:
                    writer = csv.writer(f_out, lineterminator='\n')
                    writer.writerow(['CVE ID', 'Description', 'References'])

                    logger.debug(full_path + ' is processing...')
                    for line in f_in:
                        if line == '':
                            continue
                        cveid = line.strip()
                        item = root.find('.//*[@name=\'' + cveid + '\']')
                        logger.debug(item.attrib['name'] + ' is processing...')
                        tmp_item = list()
                        tmp_item.append(cveid)
                        for elem in item:
                            tag = elem.tag.split('}')[1]
                            if tag == 'desc':
                                tmp_item.append(elem.text)
                            elif tag == 'refs':
                                tmp_str = ''
                                for ref in elem:
                                    tmp_attr = ref.attrib['source']
                                    tmp_str += tmp_attr + ':' + ref.text + '\n'
                                tmp_item.append(tmp_str)
                        writer.writerow(tmp_item)

    logger.debug('done.')