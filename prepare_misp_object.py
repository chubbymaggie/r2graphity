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
import uuid

misp_objects_path = './misp-objects/objects'


class MISPObjectGenerator():

    def __init__(self):
        self.misp_event = MISPEvent()
        self.uuid = str(uuid.uuid4())
        self.links = []

    def _fill_object(self, obj_def, values):
        empty_object = self.__new_empty_object(obj_def)
        if self.links:
            empty_object["ObjectReference"] = []
            for link in self.links:
                uuid, comment = link
                empty_object['ObjectReference'].append({'referenced_object_uuid': uuid, 'comment': comment})
        for object_type, value in values.items():
            if value.get('value') is None:
                continue
            attribute = MISPAttribute(self.misp_event.describe_types)
            value['type'] = obj_def['attributes'][object_type]['misp-attribute']
            if value.get('disable_correlation') is None:
                value['disable_correlation'] = obj_def['attributes'][object_type].get('disable_correlation')
            if value.get('to_ids') is None:
                value['to_ids'] = obj_def['attributes'][object_type].get('to_ids')
            attribute.set_all_values(**value)
            empty_object['ObjectAttribute'].append({'type': object_type, 'Attribute': attribute._json()})
        return empty_object

    def add_link(self, uuid, comment=None):
        self.links.append((uuid, comment))

    def __new_empty_object(self, object_definiton):
        return {'name': object_definiton['name'], 'meta-category': object_definiton['meta-category'],
                'uuid': self.uuid, 'description': object_definiton['description'],
                'version': object_definiton['version'], 'ObjectAttribute': []}


class FileObject(MISPObjectGenerator):

    def __init__(self, filepath):
        MISPObjectGenerator.__init__(self)
        self.filepath = filepath
        self.size = os.path.getsize(filepath)
        self.filename = os.path.basename(filepath)
        with open(filepath, 'rb') as f:
            self.pseudo_file = BytesIO(f.read())
        self.data = self.pseudo_file.getvalue()
        self.entropy = self.__entropy_H(self.data)
        self.filetype = magic.from_buffer(self.data)
        self.hashes()
        with open(os.path.join(misp_objects_path, 'file/definition.json'), 'r') as f:
            self.mo_file = json.load(f)

    def hashes(self):
        self.md5 = md5(self.data).hexdigest()
        self.sha1 = sha1(self.data).hexdigest()
        self.sha256 = sha256(self.data).hexdigest()
        self.sha512 = sha512(self.data).hexdigest()
        self.ssdeep = pydeep.hash_buf(self.data).decode()

    def __entropy_H(self, data):
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

    def dump(self):
        file_object = {}
        file_object['filename'] = {'value': self.filename}
        file_object['size-in-bytes'] = {'value': self.size}
        if not self.size:
            to_ids = False
        else:
            # MISPAttribute use the default value for the type
            to_ids = None
        # file_object['authentihash'] = self.
        file_object['ssdeep'] = {'value': self.ssdeep, 'to_ids': to_ids}
        # file_object['sha-224'] = self.
        # file_object['sha-384'] = self.
        file_object['sha512'] = {'value': self.sha512, 'to_ids': to_ids}
        # file_object['sha512/224'] = self.
        # file_object['sha512/256'] = self.
        # file_object['tlsh'] = self.
        file_object['md5'] = {'value': self.md5, 'to_ids': to_ids}
        file_object['sha1'] = {'value': self.sha1, 'to_ids': to_ids}
        file_object['sha256'] = {'value': self.sha256, 'to_ids': to_ids}
        file_object['entropy'] = {'value': self.entropy, 'to_ids': to_ids}
        return self._fill_object(self.mo_file, file_object)


class PEObject(MISPObjectGenerator):

    def __init__(self, data):
        MISPObjectGenerator.__init__(self)
        self.data = data
        with open(os.path.join(misp_objects_path, 'pe/definition.json'), 'r') as f:
            self.mo_pe = json.load(f)
        self.pe = pefile.PE(data=self.data)
        self.pe_attributes()

    def pe_attributes(self):
        if self.pe.is_dll():
            self.pe_type = 'dll'
        elif self.pe.is_driver():
            self.pe_type = 'driver'
        elif self.pe.is_exe():
            self.pe_type = 'exe'
        else:
            self.pe_type = 'unknown'
        # file_object['pehash'] = self.
        # General information
        self.imphash = self.pe.get_imphash()
        all_data = self.pe.dump_dict()
        if (all_data.get('Debug information') and all_data['Debug information'][0].get('TimeDateStamp') and
                all_data['Debug information'][0]['TimeDateStamp'].get('ISO Time')):
            self.compilation_timestamp = all_data['Debug information'][0]['TimeDateStamp']['ISO Time']
        if (all_data.get('OPTIONAL_HEADER') and all_data['OPTIONAL_HEADER'].get('AddressOfEntryPoint')):
            self.entrypoint_address = all_data['OPTIONAL_HEADER']['AddressOfEntryPoint']['Value']
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
        # Sections
        self.sections = []
        if all_data.get('PE Sections'):
            pos = 0
            for s in all_data['PE Sections']:
                s_obj = self.pe.sections[pos]
                section = PESectionObject(s, s_obj.get_data())
                self.add_link(section.uuid, 'Section {} of PE'.format(pos))
                if ((self.entrypoint_address >= s['VirtualAddress']['Value']) and
                        (self.entrypoint_address < (s['VirtualAddress']['Value'] + s['Misc_VirtualSize']['Value']))):
                    self.entrypoint_section = (s['Name']['Value'], pos)  # Tuple: (section_name, position)
                pos += 1
                self.sections.append(section)
        self.nb_sections = len(self.sections)
        # TODO: TLSSection / DIRECTORY_ENTRY_TLS

    def dump(self):
        pe_object = {}
        pe_object['type'] = {'value': self.pe_type}
        if hasattr(self, 'imphash'):
            pe_object['imphash'] = {'value': self.imphash}
        if hasattr(self, 'original_filename'):
            pe_object['original-filename'] = {'value': self.original_filename}
        if hasattr(self, 'internal_filename'):
            pe_object['internal-filename'] = {'value': self.internal_filename}
        if hasattr(self, 'compilation_timestamp'):
            pe_object['compilation-timestamp'] = {'value': self.compilation_timestamp}
        if hasattr(self, 'entrypoint_section'):
            pe_object['entrypoint-section|position'] = {'value': '{}|{}'.format(*self.entrypoint_section)}
        if hasattr(self, 'entrypoint_address'):
            pe_object['entrypoint-address'] = {'value': self.entrypoint_address}
        if hasattr(self, 'file_description'):
            pe_object['file-description'] = {'value': self.file_description}
        if hasattr(self, 'file_version'):
            pe_object['file-version'] = {'value': self.file_version}
        if hasattr(self, 'lang_id'):
            pe_object['lang-id'] = {'value': self.lang_id}
        if hasattr(self, 'product_name'):
            pe_object['product-name'] = {'value': self.product_name}
        if hasattr(self, 'product_version'):
            pe_object['product-version'] = {'value': self.product_version}
        if hasattr(self, 'company_name'):
            pe_object['company-name'] = {'value': self.company_name}
        if hasattr(self, 'nb_sections'):
            pe_object['number-sections'] = {'value': self.nb_sections}
        return self._fill_object(self.mo_pe, pe_object)


class PESectionObject(MISPObjectGenerator):

    def __init__(self, section_info, data):
        MISPObjectGenerator.__init__(self)
        self.section_info = section_info
        self.data = data
        with open(os.path.join(misp_objects_path, 'pe-section/definition.json'), 'r') as f:
            self.mo_pe_section = json.load(f)
        self.section_attributes()

    def section_attributes(self):
        self.name = self.section_info['Name']['Value']
        self.size = self.section_info['SizeOfRawData']['Value']
        self.entropy = self.section_info['Entropy']
        self.md5 = self.section_info['MD5']
        self.sha1 = self.section_info['SHA1']
        self.sha256 = self.section_info['SHA256']
        self.sha512 = self.section_info['SHA512']
        self.ssdeep = pydeep.hash_buf(self.data).decode()

    def dump(self):
        section = {}
        section['name'] = {'value': self.name}
        section['size-in-bytes'] = {'value': self.size}
        if not self.size:
            to_ids = False
        else:
            # MISPAttribute use the default value for the type
            to_ids = None
        section['entropy'] = {'value': self.entropy}
        section['md5'] = {'value': self.md5, 'to_ids': to_ids}
        section['sha1'] = {'value': self.sha1, 'to_ids': to_ids}
        section['sha256'] = {'value': self.sha256, 'to_ids': to_ids}
        section['sha512'] = {'value': self.sha512, 'to_ids': to_ids}
        section['ssdeep'] = {'value': self.ssdeep, 'to_ids': to_ids}
        return self._fill_object(self.mo_pe_section, section)


def make_objects(filepath):
    misp_file = FileObject(filepath)
    try:
        misp_pe = PEObject(misp_file.data)
        misp_file.add_link(misp_pe.uuid, 'PE indicators')
        file_object = misp_file.dump()
        pe_object = misp_pe.dump()
        pe_sections = []
        for s in misp_pe.sections:
            pe_sections.append(s.dump())
        return file_object, pe_object, pe_sections
    except pefile.PEFormatError:
        pass
    file_object = misp_file.dump()
    return file_object, None, None


if __name__ == '__main__':
    import glob
    for f in glob.glob('/path/to/samples/*'):
        fo, peo, seos = make_objects(f)
        #print(json.dumps([fo, peo, seos]))
        #break
