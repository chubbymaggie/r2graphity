#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pefile
import pydeep
from pymisp import MISPEvent, MISPAttribute
import os
from io import BytesIO
from hashlib import md5, sha1, sha256, sha512
import magic
import math
from collections import Counter
import json

misp_objects_path = './misp-objects/objects'


class PEObject(object):

    def __init__(self, filepath):
        self.filepath = filepath
        self.size = os.path.getsize(filepath)
        self.filename = os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            self.pseudo_file = BytesIO(f.read())
        self.data = self.pseudo_file.getvalue()
        self.entropy = self.entropy_H(self.data)
        self.filetype = magic.from_buffer(self.data)
        self.misp_event = MISPEvent()

    def hashes(self):
        self.md5 = md5(self.data).hexdigest()
        self.sha1 = sha1(self.data).hexdigest()
        self.sha256 = sha256(self.data).hexdigest()
        self.sha512 = sha512(self.data).hexdigest()
        self.ssdeep = pydeep.hash_buf(self.data).decode()

    def entropy_H(self, data):
        """Calculate the entropy of a chunk of data."""
        # NOTE: copy of the entropy function from pefile, the entropy of the
        # full file isn't computed

        if len(data) == 0:
            return 0.0

        occurences = Counter(bytearray(data))

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

        return entropy

    def misp_object_loader(self):
        # Simple loader for file, pe and pe-section
        with open(os.path.join(misp_objects_path, 'file/definition.json'), 'r') as f:
            self.mo_file = json.load(f)
        with open(os.path.join(misp_objects_path, 'pe/definition.json'), 'r') as f:
            self.mo_pe = json.load(f)
        with open(os.path.join(misp_objects_path, 'pe-section/definition.json'), 'r') as f:
            self.mo_pe_section = json.load(f)

    def new_empty_object(self, object_definiton):
        return {'name': object_definiton['name'], 'meta-category': object_definiton['meta-category'],
                'description': object_definiton['description'], 'version': object_definiton['version'],
                'ObjectAttribute': []}

    def pe_attributes(self):
        pe = pefile.PE(data=self.data)
        # General information
        self.imphash = pe.get_imphash()
        all_data = pe.dump_dict()
        if (all_data.get('Debug information') and all_data['Debug information'][0].get('TimeDateStamp') and
                all_data['Debug information'][0]['TimeDateStamp'].get('ISO Time')):
            self.compilation_timestamp = all_data['Debug information'][0]['TimeDateStamp']['ISO Time']
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
        if all_data.get('File Info'):
            self.original_filename = all_data['File Info'][1].get('OriginalFilename')
            self.internal_filename = all_data['File Info'][1].get('InternalName')
            self.file_description = all_data['File Info'][1].get('FileDescription')
            self.file_version = all_data['File Info'][1].get('FileVersion')
            self.lang_id = all_data['File Info'][1].get('LangID')
            self.product_name = all_data['File Info'][1].get('ProductName')
            self.product_version = all_data['File Info'][1].get('ProductVersion')
            self.company_name = all_data['File Info'][1].get('CompanyName')
            self.legal_copyright = all_data['File Info'][1].get('LegalCopyright')
        # TODO: TLSSection / DIRECTORY_ENTRY_TLS

    def make_objects(self):
        self.misp_object_loader()
        self.hashes()
        file_object = {}
        file_object['filename'] = self.filename
        file_object['size-in-bytes'] = self.size
        # file_object['authentihash'] = self.
        file_object['ssdeep'] = self.ssdeep
        # file_object['pehash'] = self.
        # file_object['sha-224'] = self.
        # file_object['sha-384'] = self.
        file_object['sha512'] = self.sha512
        # file_object['sha512/224'] = self.
        # file_object['sha512/256'] = self.
        # file_object['tlsh'] = self.
        file_object['md5'] = self.md5
        file_object['sha1'] = self.sha1
        file_object['sha256'] = self.sha256
        file_object['entropy'] = self.entropy

        self.pe_attributes()
        pe_object = {}
        if hasattr(self, 'imphash'):
            pe_object['imphash'] = self.imphash
        if hasattr(self, 'original_filename'):
            pe_object['original-filename'] = self.original_filename
        if hasattr(self, 'internal_filename'):
            pe_object['internal-filename'] = self.internal_filename
        if hasattr(self, 'compilation_timestamp'):
            pe_object['compilation-timestamp'] = self.compilation_timestamp
        if hasattr(self, 'entrypoint_section'):
            pe_object['entrypoint-section|position'] = '{}|{}'.format(*self.entrypoint_section)
        if hasattr(self, 'entrypoint_address'):
            pe_object['entrypoint-address'] = self.entrypoint_address
        if hasattr(self, 'file_description'):
            pe_object['file-description'] = self.file_description
        if hasattr(self, 'file_version'):
            pe_object['file-version'] = self.file_version
        if hasattr(self, 'lang_id'):
            pe_object['lang-id'] = self.lang_id
        if hasattr(self, 'product_name'):
            pe_object['product-name'] = self.product_name
        if hasattr(self, 'product_version'):
            pe_object['product-version'] = self.product_version
        if hasattr(self, 'company_name'):
            pe_object['company-name'] = self.company_name
        if hasattr(self, 'sections'):
            pe_sections = []
            for s in self.sections:
                section_object = {}
                section_object['name'] = s['name']
                section_object['size-in-bytes'] = s['size']
                section_object['entropy'] = s['entropy']
                section_object['md5'] = s['md5']
                section_object['sha1'] = s['sha1']
                section_object['sha256'] = s['sha256']
                section_object['sha512'] = s['sha512']
                pe_sections.append(section_object)

        fo = self.new_empty_object(self.mo_file)
        for mo_key, value in file_object.items():
            attribute = MISPAttribute(self.misp_event.describe_types)
            attribute.set_all_values(type=self.mo_file['attributes'][mo_key]['misp-attribute'], value=value)
            fo['ObjectAttribute'].append({'type': mo_key, 'Attribute': attribute._json()})

        if pe_object:
            peo = self.new_empty_object(self.mo_pe)
            for mo_key, value in pe_object.items():
                if value is None:
                    # Not sure if bug, or just empty value
                    continue
                attribute = MISPAttribute(self.misp_event.describe_types)
                attribute.set_all_values(type=self.mo_pe['attributes'][mo_key]['misp-attribute'], value=value)
                peo['ObjectAttribute'].append({'type': mo_key, 'Attribute': attribute._json()})

        if pe_sections:
            peso = []
            for s in pe_sections:
                so = self.new_empty_object(self.mo_pe_section)
                for mo_key, value in s.items():
                    attribute = MISPAttribute(self.misp_event.describe_types)
                    attribute.set_all_values(type=self.mo_pe_section['attributes'][mo_key]['misp-attribute'], value=value)
                    so['ObjectAttribute'].append({'type': mo_key, 'Attribute': attribute._json()})
                peso.append(so)
        return fo, peo, peso
