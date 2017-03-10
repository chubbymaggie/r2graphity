#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pefile
import pydeep
# from pymisp import PyMISP, MISPEvent
import os
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import magic


class PEObject(object):

    def __init__(self, filepath):
        self.filepath = filepath
        self.size = os.path.getsize(filepath)
        self.filename = os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            self.pseudo_file = BytesIO(f.read())
        self.data = self.pseudo_file.getvalue()
        self.filetype = magic.from_buffer(self.data)

    def hashes(self):
        self.md5 = md5(self.data).hexdigest()
        self.sha1 = sha1(self.data).hexdigest()
        self.sha256 = sha256(self.data).hexdigest()
        self.sha512 = sha512(self.data).hexdigest()
        self.ssdeep = pydeep.hash_buf(self.data)

    def pe_attributes(self):
        pe = pefile.PE(data=self.data)
        # General information
        self.imphash = pe.get_imphash()
        all_data = pe.dump_dict()
        if (all_data.get('Debug information') and all_data['Debug information'].get('TimeDateStamp') and
                all_data['Debug information']['TimeDateStamp'].get('ISO Time')):
            self.compilation_timestamp = all_data['Debug information']['TimeDateStamp']['ISO Time']
        if (all_data.get('OPTIONAL_HEADER') and all_data['OPTIONAL_HEADER'].get('AddressOfEntryPoint')):
            self.entrypoint_address = all_data['OPTIONAL_HEADER']['AddressOfEntryPoint']['Value']
        if pe.is_dll():
            self.pe_type = 'dll'
        elif pe.is_driver():
            self.pe_type = 'driver'
        elif pe.is_exe():
            self.pe_type = 'exe'
        else:
            self.pe_type = 'unknown'
        # Sections
        self.sections = []
        if all_data.get('PE Sections'):
            pos = 0
            for s in all_data['PE Sections']:
                section = {}
                section['name'] = s['Name']['Value']
                section['size'] = s['SizeOfRawData']['Value']
                section['entropy'] = s['Entropy']
                section['md5'] = s['MD5']
                section['sha1'] = s['SHA1']
                section['sha256'] = s['SHA256']
                section['sha512'] = s['SHA512']
                if ((self.entrypoint_address >= s['VirtualAddress']['Value']) and
                        (self.entrypoint_address < (s['VirtualAddress']['Value'] + s['Misc_VirtualSize']['Value']))):
                    self.entrypoint_section = (s['Name']['Value'], pos)  # Tuple: (section_name, position)
                pos += 1
                self.sections.append(section)
        self.nb_sections = len(self.sections)
        # TODO: TLSSection / DIRECTORY_ENTRY_TLS
