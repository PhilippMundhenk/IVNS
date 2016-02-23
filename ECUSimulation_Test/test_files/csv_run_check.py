#!/usr/bin/python
'''
Created on 25 Aug, 2015

@author: artur.mrowca
'''
from tools.general import General
import sys
import csv
import unittest2 as unittest
import subprocess
import os
import time


from components.security.ecu.types.impl_ecu_secure import StdSecurECUTimingFunctions

from configparser import ConfigParser
import numpy
import datetime
from tools import general

class CSVRunLWATest(unittest.TestCase):
    '''
        Classes under test: (Regular)SecureECU, StdSecureECUTimingFunctions, SecureCommModule
    
        This class tests the correct output of the csv file for 
        all available configurations. This is done by counting the number of expected
        appearances.
    '''

    def __init__(self, par):
        if par != None:
            unittest.TestCase.__init__(self, par)
        
        self.start_path = r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic"
        self.fil = os.path.join(self.start_path, "test_config.ini")
        self.arg_out = "result.csv"
        self.log_out = "log_out.o"
        
    '''===========================================================================
             Setup/Teardown
    ==========================================================================='''
    def setUp(self):    
        
        # vary the parameters in ArchConfig        
        os.chdir(self.start_path)
        
        # run a test.py from cmd with various parameters and test if it was successful
#         subprocess.call(["python", "test.py"])
        
   

    def _write_config(self, asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length):
        
        cfg = ConfigParser()
                        
        # create config 
        cfgfile = open(self.fil, 'w')
        cfg.add_section("Test")
        cfg.set("Test", "asym_algorithm", str(asym_alg))
        cfg.set("Test", "asym_key_length", str(asym_key))
        cfg.set("Test", "asym_option", str(asym_option))
        cfg.set("Test", "sym_algorithm", str(sym_alg))
        cfg.set("Test", "sym_key_length", str(sym_key))
        cfg.set("Test", "sym_mode", str(sym_mode))
        cfg.set("Test", "hash_mech", str(hash_mech))
        cfg.set("Test", "ca_length", str(ca_length))
        
        # write file
        cfg.write(cfgfile)
        cfgfile.close()
        
        
    def test_TESLA_record(self):
        return
        ''' 
            record tesla 
        ''' 
        os.chdir(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic")
        # minimal check (short but checks necessary stuff)
        minimal = False
        continue_from = 1
        
        # 1. vary the ArchConfig 
        self.arch_config_asyms = [['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512'], ['65537']]]  # [['AsymAuthMechEnum.ECC', ['AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_384', 'AuKeyLengthEnum.bit_256', 'AuKeyLengthEnum.bit_521'], ["None"]], \
#                                  ['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512', 'AuKeyLengthEnum.bit_1024', 'AuKeyLengthEnum.bit_2048'], ['3', '5', '17', '257', '65537']]]
        
        self.arch_config_syms = [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128'], ['SymAuthMechEnum.CBC']]]  # [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128', 'AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_256'], \
        # ['SymAuthMechEnum.CBC', 'SymAuthMechEnum.CCM', 'SymAuthMechEnum.CMAC', 'SymAuthMechEnum.CTR', 'SymAuthMechEnum.ECB']]]  # bei tesla macht nur cmac sinn
        
        self.hash_mechs = ['HashMechEnum.MD5']  # , 'HashMechEnum.SHA1', 'HashMechEnum.SHA256']
        ca_length = 2
        

        # 2. vary the ecu config       
        interpreter = True 
        ecus = list(numpy.arange(3, 104, 3))
        messages = [730]  # list(numpy.arange(10, 1050, 30))
        buses = [1]  # list(numpy.arange(1, 10, 4))
        receiversPerStreamCoeff = [0.2]  # list(numpy.arange(0.2, 1, 0.2))
        streamPerECU_MAD = [0.2]  # list(numpy.arange(0.2, 1, 0.2))
        libs = ["CyaSSL"]  # , "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        if minimal:
            ecus = list(numpy.arange(2, 3, 3))
            messages = list(numpy.arange(5, 6, 25))
            buses = list(numpy.arange(1, 2, 1))
            receiversPerStreamCoeff = list(numpy.arange(0.2, 0.4, 0.2))
            streamPerECU_MAD = list(numpy.arange(0.2, 0.4, 0.2))
            libs = ["CyaSSL"]  # , "Crypto_Lib_SW", "Crypto_Lib_HW"]
                
        # teste erstmal nur mit ecu config
        test_count = 0
        for rps_coeff in receiversPerStreamCoeff:
            for spe in streamPerECU_MAD:
                for bus_nr in buses:
                    for ecu_nr in ecus:                    
                        if bus_nr > ecu_nr: continue
                        for message_nr in messages:                            
                            for lib in libs:
                                    
                                    # configs
                                    for asym in self.arch_config_asyms:
                                        asym_alg = asym[0]
                                        for asym_key in asym[1]:
                                            for asym_option in asym[2]:
                                                for sym in self.arch_config_syms:
                                                    sym_alg = sym[0]
                                                    for sym_key in sym[1]:
                                                        for sym_mode in sym[2]: 
                                                            for hash_mech in self.hash_mechs:
                                                                
                                                                # outpath 
                                                                arg_out = "lib_tesla_%s_ecus_%s_buses_%s_msgs_%s.csv" % (lib, ecu_nr, bus_nr, message_nr)
                                                                filename = arg_out
                                                                
                                                                # write config
                                                                self._write_config(asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length)
                                                                
                                                                test_count += 1
                                                                if test_count < continue_from: continue
                                                                
                                                                # create script
                                                                arg_interpr = "-v" + "interpreter"
                                                                arg_config = "-d" + str(self.fil)
                                                                arg_lib = "-q" + str(lib)
                                                                arg_type = "-p" + str("tesla")
                                                                arg_lib2 = "-w" + str(lib)
                                                                arg_spe = "-s " + str(spe)
                                                                arg_rps = "-r " + str(rps_coeff)
                                                                arg_out = "-o " + str(arg_out)
                                                                arg_ecu = "-e " + str(ecu_nr)
                                                                arg_bus = "-b " + str(bus_nr)
                                                                arg_msg = "-m " + str(message_nr)
                                                                print("\nRunning Test Number: %s" % test_count)
                                                                if interpreter:
                                                                    # suche nach corresponding datei und zocke mir da die simulationszeit raus
                                                                    file2 = os.path.join(r"D:\Test_runs\rapid", filename)
                                                                    sim_time = "-t" + str(round(float(open(file2).readlines()[-2:-1][0].split(";")[0]) + 100))                                                               
                                                                    start_script = ["python", r"test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config, arg_type, arg_interpr, sim_time]
                                                                else:
                                                                    arg_out = "-o " + filename[:-4] + "_RAPID.csv"
                                                                    start_script = ["python", r"test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config, arg_type ]
                                                                print("Script: %s" % start_script)
                                                                print("Config: %s" % str([asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length]))
                                                                print("Running...")
                                                                
                                                                process = subprocess.Popen(start_script, stdout=subprocess.PIPE)
                                                                out, err = process.communicate()
                                                                
                                                                import shutil
                                                                if interpreter:
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tesla_%s_ecus_%s_buses_%s_msgs_%s.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tesla_%s_ecus_%s_buses_%s_msgs_%s_t_mem.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                else:
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tesla_%s_ecus_%s_buses_%s_msgs_%s_RAPID.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tesla_%s_ecus_%s_buses_%s_msgs_%s_RAPID_t_mem.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
        assert 1 == 1
        
    def test_TLS_record(self):
        ''' 
            record tls 
        ''' 
        os.chdir(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic")
        # minimal check (short but checks necessary stuff)
        minimal = False
        continue_from = 1
        
        # 1. vary the ArchConfig 
        self.arch_config_asyms = [['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512'], ['65537']]]  # [['AsymAuthMechEnum.ECC', ['AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_384', 'AuKeyLengthEnum.bit_256', 'AuKeyLengthEnum.bit_521'], ["None"]], \
#                                  ['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512', 'AuKeyLengthEnum.bit_1024', 'AuKeyLengthEnum.bit_2048'], ['3', '5', '17', '257', '65537']]]
        
        self.arch_config_syms = [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128'], ['SymAuthMechEnum.CBC']]]  # [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128', 'AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_256'], \
        # ['SymAuthMechEnum.CBC', 'SymAuthMechEnum.CCM', 'SymAuthMechEnum.CMAC', 'SymAuthMechEnum.CTR', 'SymAuthMechEnum.ECB']]]  # bei tesla macht nur cmac sinn
        
        self.hash_mechs = ['HashMechEnum.MD5']  # , 'HashMechEnum.SHA1', 'HashMechEnum.SHA256']
        ca_length = 2
        

        # 2. vary the ecu config   
        interpreter = True 
        ecus = [69]  # list(numpy.arange(3, 104, 3))
        messages = list(numpy.arange(310, 1050, 60))
        buses = [1]  # list(numpy.arange(1, 10, 4))
        receiversPerStreamCoeff = [0.2]  # list(numpy.arange(0.2, 1, 0.2))
        streamPerECU_MAD = [0.2]  # list(numpy.arange(0.2, 1, 0.2))
        libs = ["CyaSSL"]  # , "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        if minimal:
            ecus = list(numpy.arange(2, 3, 3))
            messages = list(numpy.arange(5, 6, 25))
            buses = list(numpy.arange(1, 2, 1))
            receiversPerStreamCoeff = list(numpy.arange(0.2, 0.4, 0.2))
            streamPerECU_MAD = list(numpy.arange(0.2, 0.4, 0.2))
            libs = ["CyaSSL"]  # , "Crypto_Lib_SW", "Crypto_Lib_HW"]
                
        # teste erstmal nur mit ecu config
        test_count = 0
        for rps_coeff in receiversPerStreamCoeff:
            for spe in streamPerECU_MAD:
                for bus_nr in buses:
                    for ecu_nr in ecus:                    
                        if bus_nr > ecu_nr: continue
                        for message_nr in messages:                            
                            for lib in libs:
                                    
                                    # configs
                                    for asym in self.arch_config_asyms:
                                        asym_alg = asym[0]
                                        for asym_key in asym[1]:
                                            for asym_option in asym[2]:
                                                for sym in self.arch_config_syms:
                                                    sym_alg = sym[0]
                                                    for sym_key in sym[1]:
                                                        for sym_mode in sym[2]: 
                                                            for hash_mech in self.hash_mechs:
                                                                
                                                                # outpath 
                                                                arg_out = "lib_tls_%s_ecus_%s_buses_%s_msgs_%s.csv" % (lib, ecu_nr, bus_nr, message_nr)
                                                                filename = arg_out
                                                                
                                                                # write config
                                                                self._write_config(asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length)
                                                                
                                                                test_count += 1
                                                                if test_count < continue_from: continue
                                                                
                                                                # create script
                                                                arg_interpr = "-v" + "interpreter"
                                                                arg_config = "-d" + str(self.fil)
                                                                arg_lib = "-q" + str(lib)
                                                                arg_type = "-p" + str("tls")
                                                                arg_lib2 = "-w" + str(lib)
                                                                arg_spe = "-s " + str(spe)
                                                                arg_rps = "-r " + str(rps_coeff)
                                                                arg_out = "-o " + str(arg_out)
                                                                arg_ecu = "-e " + str(ecu_nr)
                                                                arg_bus = "-b " + str(bus_nr)
                                                                arg_msg = "-m " + str(message_nr)
                                                                print("\nRunning Test Number: %s" % test_count)
                                                                if interpreter:
                                                                    # suche nach corresponding datei und zocke mir da die simulationszeit raus
                                                                    try:
                                                                        file2 = os.path.join(r"D:\Test_runs\rapid", filename)
                                                                        sim_time = "-t" + str(round(float(open(file2).readlines()[-2:-1][0].split(";")[0]) + 100))    
                                                                    except:
                                                                        continue                                                           
                                                                    start_script = ["python", r"test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config, arg_type, arg_interpr, sim_time]
                                                                else:
                                                                    arg_out = "-o " + filename[:-4] + "_RAPID.csv"
                                                                    start_script = ["python", r"test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config, arg_type ]
                                                                print("Script: %s" % start_script)
                                                                print("Config: %s" % str([asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length]))
                                                                print("Running...")
                                                                
                                                                process = subprocess.Popen(start_script, stdout=subprocess.PIPE)
                                                                out, err = process.communicate()
                                                                
                                                                import shutil
                                                                if interpreter:
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tls_%s_ecus_%s_buses_%s_msgs_%s.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tls_%s_ecus_%s_buses_%s_msgs_%s_t_mem.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                     
                                                                else:
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tls_%s_ecus_%s_buses_%s_msgs_%s_RAPID.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_tls_%s_ecus_%s_buses_%s_msgs_%s_RAPID_t_mem.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
        assert 1 == 1
        
    def test_LWA_record(self):
        return
        ''' 
            record lwa 
        ''' 
        os.chdir(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic")
        # minimal check (short but checks necessary stuff)
        minimal = False
        continue_from = 1
        
        # 1. vary the ArchConfig 
        self.arch_config_asyms = [['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512'], ['65537']]]  # [['AsymAuthMechEnum.ECC', ['AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_384', 'AuKeyLengthEnum.bit_256', 'AuKeyLengthEnum.bit_521'], ["None"]], \
#                                  ['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512', 'AuKeyLengthEnum.bit_1024', 'AuKeyLengthEnum.bit_2048'], ['3', '5', '17', '257', '65537']]]
        
        self.arch_config_syms = [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128'], ['SymAuthMechEnum.CBC']]]  # [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128', 'AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_256'], \
        # ['SymAuthMechEnum.CBC', 'SymAuthMechEnum.CCM', 'SymAuthMechEnum.CMAC', 'SymAuthMechEnum.CTR', 'SymAuthMechEnum.ECB']]]  # bei tesla macht nur cmac sinn
        
        self.hash_mechs = ['HashMechEnum.MD5']  # , 'HashMechEnum.SHA1', 'HashMechEnum.SHA256']
        ca_length = 2
        
                

        # 2. vary the ecu config    
        interpreter = True 
        ecus = [69]  # list(numpy.arange(69, 104, 3))
        messages = list(numpy.arange(10, 1050, 30))
        buses = [1]  # list(numpy.arange(1, 10, 4))
        receiversPerStreamCoeff = [0.2]  # list(numpy.arange(0.2, 1, 0.2))
        streamPerECU_MAD = [0.2]  # list(numpy.arange(0.2, 1, 0.2))
        libs = ["CyaSSL"]  # , "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        if minimal:
            ecus = list(numpy.arange(2, 3, 3))
            messages = list(numpy.arange(5, 6, 25))
            buses = list(numpy.arange(1, 2, 1))
            receiversPerStreamCoeff = list(numpy.arange(0.2, 0.4, 0.2))
            streamPerECU_MAD = list(numpy.arange(0.2, 0.4, 0.2))
            libs = ["CyaSSL"]  # , "Crypto_Lib_SW", "Crypto_Lib_HW"]
                
        # teste erstmal nur mit ecu config
        test_count = 0
        for rps_coeff in receiversPerStreamCoeff:
            for spe in streamPerECU_MAD:
                for bus_nr in buses:
                    for ecu_nr in ecus:                    
                        if bus_nr > ecu_nr: continue
                        for message_nr in messages:                            
                            for lib in libs:
                                    
                                    # configs
                                    for asym in self.arch_config_asyms:
                                        asym_alg = asym[0]
                                        for asym_key in asym[1]:
                                            for asym_option in asym[2]:
                                                for sym in self.arch_config_syms:
                                                    sym_alg = sym[0]
                                                    for sym_key in sym[1]:
                                                        for sym_mode in sym[2]: 
                                                            for hash_mech in self.hash_mechs:
                                                                
                                                                # outpath 
                                                                arg_out = "lib_lwa_%s_ecus_%s_buses_%s_msgs_%s.csv" % (lib, ecu_nr, bus_nr, message_nr)
                                                                filename = arg_out
                                                                
                                                                # write config
                                                                self._write_config(asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length)
                                                                
                                                                test_count += 1
                                                                if test_count < continue_from: continue
                                                                
                                                                # create script
                                                                arg_interpr = "-v" + "interpreter"
                                                                arg_config = "-d" + str(self.fil)
                                                                arg_lib = "-q" + str(lib)
                                                                arg_lib2 = "-w" + str(lib)
                                                                arg_spe = "-s " + str(spe)
                                                                arg_rps = "-r " + str(rps_coeff)
                                                                arg_out = "-o " + str(arg_out)
                                                                arg_ecu = "-e " + str(ecu_nr)
                                                                arg_bus = "-b " + str(bus_nr)
                                                                arg_msg = "-m " + str(message_nr)
                                                                print("\nRunning Test Number: %s" % test_count)
                                                                if interpreter:
                                                                    # suche nach corresponding datei und zocke mir da die simulationszeit raus
                                                                    file2 = os.path.join(r"D:\Test_runs\rapid", filename)
                                                                    sim_time = "-t" + str(round(float(open(file2).readlines()[-2:-1][0].split(";")[0]) + 100))                                                               
                                                                    start_script = ["python", r"test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config, arg_interpr, sim_time]
                                                                else:
                                                                    arg_out = "-o " + filename[:-4] + "_RAPID.csv"
                                                                    start_script = ["python", r"test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config]
                                                                print("Script: %s" % start_script)
                                                                print("Config: %s" % str([asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length]))
                                                                print("Running...")
                                                                
                                                                process = subprocess.Popen(start_script, stdout=subprocess.PIPE)
                                                                out, err = process.communicate()
                                                                
                                                                import shutil
                                                                if interpreter:
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_lwa_%s_ecus_%s_buses_%s_msgs_%s.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_lwa_%s_ecus_%s_buses_%s_msgs_%s_t_mem.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                else:
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_lwa_%s_ecus_%s_buses_%s_msgs_%s_RAPID.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                    shutil.move(os.path.join(r"C:\Users\artur.mrowca\workspace\Testcases\testcases\synthetic", " lib_lwa_%s_ecus_%s_buses_%s_msgs_%s_RAPID_t_mem.csv" % (lib, ecu_nr, bus_nr, message_nr)), \
                                                                                os.path.join(r"D:\Test_runs"))
                                                                
        assert 1 == 1
        
        
        
        
    def test_all_configurations_LWA(self):
        return
        ''' 
            this method tests the correct output of the csv file for 
            all available configurations. This is done by counting the number of expected
            appearances.
           
            1. teste wie oft es vorkommt
            2. teste Abstaende zwischen tags und schaue ob die die ich erwarte
        ''' 
        
        # minimal check (short but checks necessary stuff)
        minimal = True
        continue_from = 1
        
        # 1. vary the ArchConfig 
        self.arch_config_asyms = [['AsymAuthMechEnum.ECC', ['AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_384', 'AuKeyLengthEnum.bit_256', 'AuKeyLengthEnum.bit_521'], ["None"]], \
                                  ['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512', 'AuKeyLengthEnum.bit_1024', 'AuKeyLengthEnum.bit_2048'], ['3', '5', '17', '257', '65537']]]
        
        self.arch_config_syms = [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128', 'AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_256'], \
                                  ['SymAuthMechEnum.CBC', 'SymAuthMechEnum.CCM', 'SymAuthMechEnum.CMAC', 'SymAuthMechEnum.CTR', 'SymAuthMechEnum.ECB']]]  # bei tesla macht nur cmac sinn
        
        self.hash_mechs = ['HashMechEnum.MD5', 'HashMechEnum.SHA1', 'HashMechEnum.SHA256']
        ca_length = 2
        

        # 2. vary the ecu config        
        ecus = list(numpy.arange(15, 150, 3))
        messages = list(numpy.arange(10, 1000, 25))
        buses = list(numpy.arange(1, 10, 1))
        receiversPerStreamCoeff = list(numpy.arange(0.2, 1, 0.2))
        streamPerECU_MAD = list(numpy.arange(0.2, 1, 0.2))
        libs = ["CyaSSL", "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        if minimal:
            ecus = list(numpy.arange(2, 3, 3))
            messages = list(numpy.arange(5, 6, 25))
            buses = list(numpy.arange(1, 2, 1))
            receiversPerStreamCoeff = list(numpy.arange(0.2, 0.4, 0.2))
            streamPerECU_MAD = list(numpy.arange(0.2, 0.4, 0.2))
            libs = ["CyaSSL", "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        # teste erstmal nur mit ecu config
        test_count = 0
        for rps_coeff in receiversPerStreamCoeff:
            for spe in streamPerECU_MAD:
                for ecu_nr in ecus:
                    for bus_nr in buses:
                        if bus_nr > ecu_nr: continue
                        for message_nr in messages:                            
                            for lib in libs:
                                    
                                    # configs
                                    for asym in self.arch_config_asyms:
                                        asym_alg = asym[0]
                                        for asym_key in asym[1]:
                                            for asym_option in asym[2]:
                                                for sym in self.arch_config_syms:
                                                    sym_alg = sym[0]
                                                    for sym_key in sym[1]:
                                                        for sym_mode in sym[2]: 
                                                            for hash_mech in self.hash_mechs:
                                                                # write config
                                                                self._write_config(asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length)
                                                                
                                                                test_count += 1
                                                                if test_count < continue_from: continue
                                                                
                                                                # create script
                                                                arg_config = "-d" + str(self.fil)
                                                                arg_lib = "-q" + str(lib)
                                                                arg_lib2 = "-w" + str(lib)
                                                                arg_spe = "-s " + str(spe)
                                                                arg_rps = "-r " + str(rps_coeff)
                                                                arg_out = "-o " + str(self.arg_out)
                                                                arg_ecu = "-e " + str(ecu_nr)
                                                                arg_bus = "-b " + str(bus_nr)
                                                                arg_msg = "-m " + str(message_nr)
                                                                print("\nRunning Test Number: %s" % test_count)                            
                                                                start_script = ["python", "test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config ]
                                                                print("Script: %s" % start_script)
                                                                print("Config: %s" % str([asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length]))
                                                                print("Running...")
                                                                
                                                                # run script
                                                                output = subprocess.Popen(start_script, stdout=subprocess.PIPE).communicate()[0]
                                                                
                                                                # init information to extract
                                                                seed_used = None
                                                                streams = []  # [sender_id, receiver_list, interval, stream_id, start_time]
                                                                map_start_times = {}  # key msg id val start time
                                                                
                                                                # read information
                                                                result_lines = str(output).split("\\n")
                                                                for line in result_lines:
                                                                    
                                                                    if -1 != line.find("Using random Seed"):
                                                                        seed_used = line.split(" ")[-1][:-2]
                                                                        
                                                                    if line[:4] == "ID: ":
                                                                        args = line.split(" ")
                                                                        sender_id = args[6]
                                                                        receiver_list = eval("".join(args[1 + args.index("receivers:"):]).replace("\\r", ""))
                                                                        interval = args[2].split(':')[-1]
                                                                        stream_id = args[1]                            
                                                                        streams.append([sender_id, receiver_list, interval, stream_id])
                                                                    
                                                                    if -1 != line.find("sending process for msg ID ") and line.find("is running") != -1:
                                                                        msg_id = line.split(" ")[5]
                                                                        start_time = line.split(" ")[9][:-1].replace("\\", "").replace(")", "")
                                                                        map_start_times[msg_id] = start_time
                                                                        
                                                                print ("Seed: " + str(seed_used))
                                    
                                    
                                                                # validate the output csv list
                                                                print("Validating ECU List....")
                                                                valid = self._validate_csv(streams, map_start_times, ecu_nr, bus_nr, message_nr, lib)
                                                    
                                                                # IF FAIL WRITE TO FILE WELCHER BEFEHL
                                                                if valid: print("----- SUCCESS")
                                                                else: 
                                                                    cur_time = time.strftime("%I:%M:%S")
                                                                    cur_date = time.strftime("%d/%m/%Y")        
                                                                    save_path = r"C:\Users\artur.mrowca\workspace\ECUSimulation_Test\failed_tests.txt"                     
                                                                    with open(save_path, "a") as text_file:
                                                                        text_file.write("\n\nDate: %s\nTime: %s\nSeed: %s\nFailed: %s" % (cur_date, cur_time, seed_used, start_script))
                                                                    print("----- FAILED")
                                                                    sys.exit()
            
        assert 1 == 1

    def test_all_configurations_TESLA(self):
        return   
        ''' 
            this method tests the correct output of the csv file for 
            all available configurations. This is done by counting the number of expected
            appearances.
        ''' 
        continue_from = 1
        
        # 1. vary the ArchConfig 
        self.arch_config_asyms = [['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512', 'AuKeyLengthEnum.bit_1024', 'AuKeyLengthEnum.bit_2048'], ['3', '5', '17', '257', '65537']], \
                             ['AsymAuthMechEnum.ECC', ['AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_384', 'AuKeyLengthEnum.bit_256', 'AuKeyLengthEnum.bit_521'], ["None"]],
                             ['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128', 'AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_256'], ['SymAuthMechEnum.CBC', 'SymAuthMechEnum.CCM', 'SymAuthMechEnum.CMAC', 'SymAuthMechEnum.CTR', 'SymAuthMechEnum.ECB']]]  # bei TESLA AUCH SYM als eingabe moeglich -> dann Masterkey
        
        
        self.arch_config_syms = [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128', 'AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_256'], \
                                  ['SymAuthMechEnum.CMAC']]]  # bei tesla macht nur cmac sinn
        
        ca_length = 2
        

        # 2. vary the ecu config        
        ecus = list(numpy.arange(5, 150, 3))
        messages = list(numpy.arange(15, 1000, 25))
        buses = list(numpy.arange(1, 10, 1))
        receiversPerStreamCoeff = list(numpy.arange(0.2, 1, 0.2))
        streamPerECU_MAD = list(numpy.arange(0.2, 1, 0.2))
        libs = ["CyaSSL", "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        # teste erstmal nur mit ecu config
        test_count = 0
        
        for rps_coeff in receiversPerStreamCoeff:
            for spe in streamPerECU_MAD:
                for ecu_nr in ecus:
                    for bus_nr in buses:
                        if bus_nr > ecu_nr: continue
                        for message_nr in messages:                            
                                for lib in libs:
                                                                        
                                    # configs
                                    for asym in self.arch_config_asyms:
                                        asym_alg = asym[0]
                                        for asym_key in asym[1]:
                                            for asym_option in asym[2]:
                                                for sym in self.arch_config_syms:
                                                    sym_alg = sym[0]
                                                    for sym_key in sym[1]:
                                                        for sym_mode in sym[2]: 

                                                            # write config
                                                            self._write_config(asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, 'HashMechEnum.MD5', ca_length)
                                                            
                                                            test_count += 1
                                                            
                                                            if test_count < continue_from: continue
                                                                
                                                            # create script
                                                            arg_type = "-p" + str("tesla")
                                                            arg_config = "-d" + str(self.fil)
                                                            arg_lib = "-q" + str(lib)
                                                            arg_lib2 = "-w" + str(lib)
                                                            arg_spe = "-s " + str(spe)
                                                            arg_rps = "-r " + str(rps_coeff)
                                                            arg_out = "-o " + str(self.arg_out)
                                                            arg_ecu = "-e " + str(ecu_nr)
                                                            arg_bus = "-b " + str(bus_nr)
                                                            arg_msg = "-m " + str(message_nr)
                                                            print("\nRunning Test Number: %s" % test_count)                            
                                                            start_script = ["python", "test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config, arg_type ]
                                                            print("Script: %s" % start_script)
                                                            print("Config: %s" % str([asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, 'HashMechEnum.MD5', ca_length]))
                                                            print("Time %s" % datetime.datetime.now().time())
                                                            print("Running...")
                                                            
                                                            # run script
                                                            process = subprocess.Popen(start_script, stdout=subprocess.PIPE)
                                                            out, err = process.communicate()
                                                                                                                            
                                                            # init information to extract
                                                            seed_used = None
                                                            streams = []  # [sender_id, receiver_list, interval, stream_id, start_time]
                                                            map_start_times = {}  # key msg id val start time
                                                            
                                                            # read information
                                                            result_lines = str(out).split("\\n")
                                                            for line in result_lines:
#                                                                 print(line)
                                                                if -1 != line.find("Using random Seed"):
                                                                    seed_used = line.split(" ")[-1][:-2]
                                                                    
                                                                if line[:4] == "ID: ":
                                                                    args = line.split(" ")
                                                                    sender_id = args[6]
                                                                    receiver_list = eval("".join(args[1 + args.index("receivers:"):]).replace("\\r", ""))
                                                                    interval = args[2].split(':')[-1]
                                                                    stream_id = args[1]                            
                                                                    streams.append([sender_id, receiver_list, interval, stream_id])
                                                                
                                                                if -1 != line.find("sending process for msg ID ") and line.find("is running") != -1:
                                                                    msg_id = line.split(" ")[5]
                                                                    start_time = line.split(" ")[9][:-1].replace("\\", "").replace(")", "")
                                                                    map_start_times[msg_id] = start_time
                                                                    
                                                            print ("Seed: " + str(seed_used))
                                                            
                                
                                                            # validate the output csv list
                                                            print("Validating ECU List....")
                                                            valid = self._validate_csv_tesla(streams, map_start_times, ecu_nr, bus_nr, message_nr, lib)
                                                
                                                            # IF FAIL WRITE TO FILE WELCHER BEFEHL
                                                            if valid: print("----- SUCCESS")
                                                            else: 
                                                                cur_time = time.strftime("%I:%M:%S")
                                                                cur_date = time.strftime("%d/%m/%Y")        
                                                                save_path = r"C:\Users\artur.mrowca\workspace\ECUSimulation_Test\failed_tests.txt"                     
                                                                with open(save_path, "a") as text_file:
                                                                    text_file.write("\n\nDate: %s\nTime: %s\nSeed: %s\nFailed: %s" % (cur_date, cur_time, seed_used, start_script))
                                                                print("----- FAILED")
                                                                sys.exit()
            
        assert 1 == 1

    def test_all_configurations_TLS(self):
        return
        ''' 
            this method tests the correct output of the csv file for 
            all available configurations. This is done by counting the number of expected
            appearances.
        ''' 
        
        # minimal check (short but checks necessary stuff)
        minimal = True
        continue_from = 1
        
        # 1. vary the ArchConfig 
        self.arch_config_asyms = [['AsymAuthMechEnum.ECC', ['AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_384', 'AuKeyLengthEnum.bit_256', 'AuKeyLengthEnum.bit_521'], ["None"]], \
                                  ['AsymAuthMechEnum.RSA', ['AuKeyLengthEnum.bit_512', 'AuKeyLengthEnum.bit_1024', 'AuKeyLengthEnum.bit_2048'], ['3', '5', '17', '257', '65537']]]
        
        self.arch_config_syms = [['SymAuthMechEnum.AES', ['AuKeyLengthEnum.bit_128', 'AuKeyLengthEnum.bit_192', 'AuKeyLengthEnum.bit_256'], \
                                  ['SymAuthMechEnum.CBC', 'SymAuthMechEnum.CCM', 'SymAuthMechEnum.CMAC', 'SymAuthMechEnum.CTR', 'SymAuthMechEnum.ECB']]]  # bei tesla macht nur cmac sinn
        
        self.hash_mechs = ['HashMechEnum.MD5', 'HashMechEnum.SHA1', 'HashMechEnum.SHA256']
        ca_length = 2
        

        # 2. vary the ecu config        
        ecus = list(numpy.arange(15, 150, 3))
        messages = list(numpy.arange(10, 1000, 25))
        buses = list(numpy.arange(1, 10, 1))
        receiversPerStreamCoeff = list(numpy.arange(0.2, 1, 0.2))
        streamPerECU_MAD = list(numpy.arange(0.2, 1, 0.2))
        libs = ["CyaSSL", "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        if minimal:
            ecus = list(numpy.arange(2, 3, 3))
            messages = list(numpy.arange(5, 6, 25))
            buses = list(numpy.arange(1, 2, 1))
            receiversPerStreamCoeff = list(numpy.arange(0.2, 0.4, 0.2))
            streamPerECU_MAD = list(numpy.arange(0.2, 0.4, 0.2))
            libs = ["CyaSSL", "Crypto_Lib_SW", "Crypto_Lib_HW"]
        
        # teste erstmal nur mit ecu config
        test_count = 0
        for rps_coeff in receiversPerStreamCoeff:
            for spe in streamPerECU_MAD:
                for ecu_nr in ecus:
                    for bus_nr in buses:
                        if bus_nr > ecu_nr: continue
                        for message_nr in messages:                            
                            for lib in libs:
                                    
                                    # configs
                                    for asym in self.arch_config_asyms:
                                        asym_alg = asym[0]
                                        for asym_key in asym[1]:
                                            for asym_option in asym[2]:
                                                for sym in self.arch_config_syms:
                                                    sym_alg = sym[0]
                                                    for sym_key in sym[1]:
                                                        for sym_mode in sym[2]: 
                                                            for hash_mech in self.hash_mechs:
                                                                # write config
                                                                self._write_config(asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length)
                                                                
                                                                test_count += 1
                                                                if test_count < continue_from: continue
                                                                
                                                                # create script
                                                                arg_type = "-p" + str("tls")
                                                                arg_config = "-d" + str(self.fil)
                                                                arg_lib = "-q" + str(lib)
                                                                arg_lib2 = "-w" + str(lib)
                                                                arg_spe = "-s " + str(spe)
                                                                arg_rps = "-r " + str(rps_coeff)
                                                                arg_out = "-o " + str(self.arg_out)
                                                                arg_ecu = "-e " + str(ecu_nr)
                                                                arg_bus = "-b " + str(bus_nr)
                                                                arg_msg = "-m " + str(message_nr)
                                                                print("\nRunning Test Number: %s" % test_count)                            
                                                                start_script = ["python", "test.py", arg_msg, arg_bus, arg_lib, arg_lib2, arg_ecu, arg_out, arg_rps, arg_spe, arg_config, arg_type ]
                                                                print("Script: %s" % start_script)
                                                                print("Config: %s" % str([asym_alg, asym_key, asym_option, sym_alg, sym_key, sym_mode, hash_mech, ca_length]))
                                                                print("Running...")
                                                                
                                                                # run script
                                                                output = subprocess.Popen(start_script, stdout=subprocess.PIPE).communicate()[0]
                                                                
                                                                # init information to extract
                                                                seed_used = None
                                                                streams = []  # [sender_id, receiver_list, interval, stream_id, start_time]
                                                                map_start_times = {}  # key msg id val start time
                                                                
                                                                # read information
                                                                result_lines = str(output).split("\\n")
                                                                for line in result_lines:
                                                                    
                                                                    if -1 != line.find("Using random Seed"):
                                                                        seed_used = line.split(" ")[-1][:-2]
                                                                        
                                                                    if line[:4] == "ID: ":
                                                                        args = line.split(" ")
                                                                        sender_id = args[6]
                                                                        receiver_list = eval("".join(args[1 + args.index("receivers:"):]).replace("\\r", ""))
                                                                        interval = args[2].split(':')[-1]
                                                                        stream_id = args[1]                            
                                                                        streams.append([sender_id, receiver_list, interval, stream_id])
                                                                    
                                                                    if -1 != line.find("sending process for msg ID ") and line.find("is running") != -1:
                                                                        msg_id = line.split(" ")[5]
                                                                        start_time = line.split(" ")[9][:-1].replace("\\", "").replace(")", "")
                                                                        map_start_times[msg_id] = start_time
                                                                        
                                                                print ("Seed: " + str(seed_used))
                                    
                                    
                                                                # validate the output csv list
                                                                print("Validating ECU List....")
                                                                valid = self._validate_csv_tls(streams, map_start_times, ecu_nr, bus_nr, message_nr, lib)
                                                    
                                                                # IF FAIL WRITE TO FILE WELCHER BEFEHL
                                                                if valid: print("----- SUCCESS")
                                                                else: 
                                                                    cur_time = time.strftime("%I:%M:%S")
                                                                    cur_date = time.strftime("%d/%m/%Y")        
                                                                    save_path = r"C:\Users\artur.mrowca\workspace\ECUSimulation_Test\failed_tests.txt"                     
                                                                    with open(save_path, "a") as text_file:
                                                                        text_file.write("\n\nDate: %s\nTime: %s\nSeed: %s\nFailed: %s" % (cur_date, cur_time, seed_used, start_script))
                                                                    print("----- FAILED")
                                                                    sys.exit()
            
        assert 1 == 1

    def _validate_csv(self, streams, map_start_times, ecu_nr, bus_nr, message_nr, library):
        
        nr_simple_messages_sent = 6
        
        appearances_expected = {}
        appearances_expected["MonitorTags.CP_SEC_INIT_AUTHENTICATION"] = 1
        appearances_expected["MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE"] = ecu_nr
        appearances_expected["MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG"] = ecu_nr
        appearances_expected["MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG"] = ecu_nr
        appearances_expected["MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE"] = ecu_nr
        appearances_expected["MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE"] = ecu_nr
        
        # per stream
        for stream in streams:
            # [sender_id, receiver_list, interval, stream_id, start_time]
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE", stream[3], 1)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE", stream[3], 1)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE", stream[3], len(stream[1]) + 1)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE", stream[3], len(stream[1]) + 1)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE", stream[3], len(stream[1]) + 1)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE", stream[3], len(stream[1]) * nr_simple_messages_sent)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE", stream[3], len(stream[1]) * nr_simple_messages_sent)
            
        appearances_expected["MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE"] = len(streams)
        appearances_expected["MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE"] = len(streams)
        appearances_expected["MonitorTags.CP_SEC_GENERATED_SESSION_KEY"] = len(streams)
        appearances_expected["MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE"] = len(streams) * nr_simple_messages_sent
        appearances_expected["MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE"] = len(streams) * nr_simple_messages_sent    

        appearances_actual = {}
        appearances_actual["MonitorTags.CP_SEC_INIT_AUTHENTICATION"] = 0
        appearances_actual["MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT"] = 0
        appearances_actual["MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE"] = 0
        appearances_actual["MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE"] = 0
        appearances_actual["MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG"] = 0
        appearances_actual["MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG"] = 0
        appearances_actual["MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE"] = 0

        # per stream
        for stream in streams:
            # [sender_id, receiver_list, interval, stream_id, start_time]
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE", stream[3], 0)

        appearances_actual["MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE"] = 0 
        appearances_actual["MonitorTags.CP_SEC_GENERATED_SESSION_KEY"] = 0
        appearances_actual["MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE"] = 0 
        appearances_actual["MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE"] = 0

        # count number of appearances
        print("Appearance count: ")
        sec = " " + self.arg_out
        with open(os.path.join(self.start_path, sec), 'rt') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=';')
            for row in spamreader:
                if not row: continue
                
                if row[3] in appearances_actual:
                    if isinstance(appearances_actual[row[3]], dict):
                        try:
                            appearances_actual[row[3]][row[6]] += 1
                        except:
                            General().add_to_three_dict(appearances_actual, row[3], row[6], 0)
                    else:
                        appearances_actual[row[3]] += 1
                        
        # compare expected to actual number
        for tag in appearances_expected:
            
            if isinstance(appearances_actual[tag], dict):
                for kk in appearances_actual[tag]:
                    if appearances_actual[tag][kk] != appearances_expected[tag][kk]:
                        print("%s, stream  %s: found %s appearances, expected %s" % (tag, kk, appearances_actual[tag][kk], appearances_expected[tag][kk]))
                        return False
            else:
                if appearances_actual[tag] != appearances_expected[tag]:
                    print("%s: found %s appearances, expected %s" % (tag, appearances_actual[tag], appearances_expected[tag]))
                    return False
        print("----> OK")
        
        # count timing
#         print("Timing Check: ")
#         print("----> OK")
        
        tf = StdSecurECUTimingFunctions(library)
        
        # timings:
        timing_tags = []
        
        # ECU: c_t_adv_msg_secmodcert_enc
        timing_tags.append(["MonitorTags.CP_ECU_RECEIVE_SEC_MOD_ADVERTISEMENT", "MonitorTags.CP_ECU_VALIDATED_SEC_MOD_CERTIFICATE"])
        
        # ECU: c_t_reg_msg_sym_keygen
        timing_tags.append(["MonitorTags.CP_ECU_START_CREATION_REG_MESSAGE", "MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE"])
        
        # ECU: c_t_ecu_auth_reg_msg_validate_cert
        timing_tags.append(["MonitorTags.CP_ECU_CREATED_ECU_KEY_REG_MESSAGE", "MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE"])
        
        # ECU: c_t_reg_msg_hash
        timing_tags.append(["MonitorTags.CP_ECU_ENCRYPTED_INNER_REG_MESSAGE", "MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE"])
        
        # ECU: c_t_reg_msg_outter_enc
        timing_tags.append(["MonitorTags.CP_ECU_HASHED_INNER_REG_MESSAGE", "MonitorTags.CP_ECU_ENCRYPTED_OUTER_REG_MESSAGE"])
        
        # SEC: c_t_ecu_auth_reg_msg_inner_dec
        timing_tags.append(["MonitorTags.CP_SEC_RECEIVE_REG_MESSAGE", "MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE"])
        
        # SEC: c_t_ecu_auth_reg_msg_outter_dec
        timing_tags.append(["MonitorTags.CP_SEC_DECRYPTED_INNER_REG_MESSAGE", "MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE"])
        
        # SEC: c_t_ecu_auth_reg_msg_validate_cert
        timing_tags.append(["MonitorTags.CP_SEC_DECRYPTED_OUTER_REG_MESSAGE", "MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE"])
        
        # SEC: c_t_ecu_auth_reg_msg_create_comp_hash
        timing_tags.append(["MonitorTags.CP_SEC_VALIDATED_ECU_CERTIFICATE", "MonitorTags.CP_SEC_CREATED_CMP_HASH_REG_MSG"])
        
        # SEC: c_t_ecu_auth_conf_msg_enc
        timing_tags.append(["MonitorTags.CP_SEC_COMPARED_HASH_REG_MSG", "MonitorTags.CP_SEC_ECNRYPTED_CONFIRMATION_MESSAGE"])
        
        # ECU: c_t_conf_msg_dec_time
        timing_tags.append(["MonitorTags.CP_ECU_RECEIVE_CONF_MESSAGE", "MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE"])
        
        
        
        # ECU: c_t_req_msg_stream_enc
        timing_tags.append(["MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE", "MonitorTags.CP_ECU_ENCRYPTED_REQ_MESSAGE"])  # pro stream
        
        # SEC: c_t_str_auth_decr_req_msg
        timing_tags.append(["MonitorTags.CP_SEC_RECEIVE_REQ_MESSAGE", "MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE"])  # pro Stream
        
        # SEC: c_t_str_auth_keygen_grant_msg
        timing_tags.append(["MonitorTags.CP_SEC_DECRYPTED_REQ_MESSAGE", "MonitorTags.CP_SEC_GENERATED_SESSION_KEY"])  # pro Stream
        

        # SEC: c_t_str_auth_enc_grant_msg
        timing_tags.append(["MonitorTags.CP_SEC_GENERATED_SESSION_KEY", "MonitorTags.CP_SEC_ENCRYPTED_GRANT_MESSAGE"])  # pro Stream gehe eh von oben nach unten
        
        
        # ECU: c_t_grant_msg_stream_dec
        timing_tags.append(["MonitorTags.CP_ECU_RECEIVE_GRANT_MESSAGE", "MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE"])
        
        
        # ECU: c_t_normal_msg_enc
        timing_tags.append(["MonitorTags.CP_ECU_INTENT_SEND_SIMPLE_MESSAGE", "MonitorTags.CP_ECU_ENCRYPTED_SEND_SIMPLE_MESSAGE"])
        
        # ECU: c_t_normal_msg_dec
        timing_tags.append(["MonitorTags.CP_ECU_RECEIVE_SIMPLE_MESSAGE", "MonitorTags.CP_ECU_DECRYPTED_SIMPLE_MESSAGE"])
        
        
        
        
        # check time between checkpoints
        
        
        return True

    def _validate_csv_tesla(self, streams, map_start_times, ecu_nr, bus_nr, message_nr, library):
        
        nr_sync_messages = self._get_expected_sync_msgs(streams)
        nr_simple_messages_sent = 5
        nr_receivers = sum([len(stream[1]) for stream in streams])
        
        senders = []
        for stream in streams:
            if stream[0] not in senders:
                senders.append(stream[0])
        nr_sender = len(senders)
            
        
        appearances_expected = {}
        appearances_expected["MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN"] = nr_receivers
        appearances_expected["MonitorTags.CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN"] = nr_receivers
        appearances_expected["MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN"] = nr_receivers
        appearances_expected["MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE"] = nr_sync_messages
        appearances_expected["MonitorTags.CP_SETUP_INIT_CREATE_KEYS"] = nr_sender
        appearances_expected["MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS"] = nr_sender
        
        # per stream
        for stream in streams:
            # [sender_id, receiver_list, interval, stream_id, start_time]
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_CHECK_KEY_LEGID", stream[3], nr_simple_messages_sent * len(stream[1]))
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_CHECKED_KEY_LEGID", stream[3], nr_simple_messages_sent * len(stream[1]))
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE", stream[3], (nr_simple_messages_sent - 1) * (len(stream[1]) - 1))  # here condition bigger than 3 messages as it is possible that the sender sends in the same interval and the key for a message is not yet disclosed
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_EXCHANGE_FIRST_KEY_KN", stream[3], len(stream[1]))
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_TRANSMIT_MESSAGE", stream[3], nr_simple_messages_sent)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE", stream[3], (nr_simple_messages_sent - 1) * (len(stream[1]) - 1))  # here condition bigger than 3 messages as it is possible that the sender sends in the same interval and the key for a message is not yet disclosed
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_MACED_TRANSMIT_MESSAGE", stream[3], nr_simple_messages_sent)
            
        appearances_actual = {}
        appearances_actual["MonitorTags.CP_RECEIVED_EXCHANGE_FIRST_KEY_KN"] = 0
        appearances_actual["MonitorTags.CP_DECRYPTED_EXCHANGE_FIRST_KEY_KN"] = 0
        appearances_actual["MonitorTags.CP_ENCRYPTED_EXCHANGE_FIRST_KEY_KN"] = 0
        appearances_actual["MonitorTags.CP_RECEIVE_SYNC_RESPONSE_MESSAGE"] = 0
        appearances_actual["MonitorTags.CP_SETUP_INIT_CREATE_KEYS"] = 0
        appearances_actual["MonitorTags.CP_SETUP_FINISHED_CREATE_KEYS"] = 0
        
        # per stream
        for stream in streams:
            # [sender_id, receiver_list, interval, stream_id, start_time]
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_CHECK_KEY_LEGID", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_CHECKED_KEY_LEGID", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_EXCHANGE_FIRST_KEY_KN", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_TRANSMIT_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_MACED_TRANSMIT_MESSAGE", stream[3], 0)
            

        # count number of appearances
        print("Appearance count: ")
        sec = " " + self.arg_out
        with open(os.path.join(self.start_path, sec), 'rt') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=';')
            for row in spamreader:
                if not row: continue
                
                if row[3] in appearances_actual:
                    if isinstance(appearances_actual[row[3]], dict):
                        try:
                            appearances_actual[row[3]][row[6]] += 1
                        except:
                            General().add_to_three_dict(appearances_actual, row[3], row[6], 0)
                    else:
                        appearances_actual[row[3]] += 1
                        
        # compare expected to actual number
        for tag in appearances_expected:
            
            if isinstance(appearances_actual[tag], dict):
                for kk in appearances_actual[tag]:
                    
                    if tag in ["MonitorTags.CP_INIT_VERIFYING_BUFFER_MESSAGE", "MonitorTags.CP_FINISHED_VERIFYING_BUFFER_MESSAGE"]:
                        if appearances_actual[tag][kk] < appearances_expected[tag][kk]:
                            print("%s, stream  %s: found %s appearances, expected more or equal to %s" % (tag, kk, appearances_actual[tag][kk], appearances_expected[tag][kk]))
                            return False
                    
                    elif appearances_actual[tag][kk] != appearances_expected[tag][kk]:
                        print("%s, stream  %s: found %s appearances, expected %s" % (tag, kk, appearances_actual[tag][kk], appearances_expected[tag][kk]))
                        return False
            else:
                if appearances_actual[tag] != appearances_expected[tag]:
                    print("%s: found %s appearances, expected %s" % (tag, appearances_actual[tag], appearances_expected[tag]))
                    return False
                
        return True

    def _validate_csv_tls(self, streams, map_start_times, ecu_nr, bus_nr, message_nr, library):
        
        nr_simple_messages_sent = 5
        
        nr_receivers = self._get_number_receivers_map(streams)
        
        appearances_expected = {}
        
        # per stream
        for stream in streams:
            # [sender_id, receiver_list, interval, stream_id, start_time]
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_CLIENT_HELLO", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_CLIENT_AUTHENTICATED", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE", stream[3], nr_receivers[stream[3]])            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED", stream[3], nr_receivers[stream[3]])            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED", stream[3], nr_receivers[stream[3]])     
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_CLIENT_FINISHED", stream[3], nr_receivers[stream[3]])            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_HASHED_CLIENT_FINISHED", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_HASHED_SERVER_FINISHED", stream[3], nr_receivers[stream[3]])            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE", stream[3], nr_receivers[stream[3]])            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_INIT_SERVER_FINISHED", stream[3], nr_receivers[stream[3]])            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_CLIENT_HELLO", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_SERVER_HELLO", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_CLIENT_FINISHED", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_SERVER_FINISHED", stream[3], nr_receivers[stream[3]])            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE", stream[3], nr_receivers[stream[3]] * nr_simple_messages_sent)
            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_CERTIFICATE_REQUEST", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_CLIENT_CERTIFICATE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_CIPHER_SPEC", stream[3], nr_receivers[stream[3]] * 2)
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC", stream[3], nr_receivers[stream[3]] * 2)
            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_CLIENT_HELLO", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_SERVER_HELLO", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_SERVER_CERTIFICATE", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SEND_SERVER_HELLO_DONE", stream[3], nr_receivers[stream[3]])
            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF", stream[3], nr_receivers[stream[3]])
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SERVER_AUTHENTICATED", stream[3], nr_receivers[stream[3]])
            
            General().add_to_three_dict(appearances_expected, "MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE", stream[3], nr_receivers[stream[3]] * nr_simple_messages_sent)
            
            
        appearances_actual = {}
        
        # per stream
        for stream in streams:
            # [sender_id, receiver_list, interval, stream_id, start_time]
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_CLIENT_HELLO", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_CLIENT_AUTHENTICATED", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_CLIENT_CERTIFICATE_VALIDATED", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_CLIENT_FINISHED_GENERATED_HASH_PRF", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_CLIENT_FINISHED_HASHED_COMPARISON_HASH", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_DECRYPTED_CERTIFICATE_VERIFY", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_DECRYPTED_CLIENT_KEYEXCHANGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ENCRYPTED_CERTIFICATE_VERIFY", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_ENCRYPTED_CLIENT_KEYEXCHANGE", stream[3], 0)            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_GENERATED_HASH_FROM_PRF_CLIENT_FINISHED", stream[3], 0)            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_GENERATED_MASTERSEC_CLIENT_KEYEXCHANGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_GENERATED_MASTER_SECRET_CERT_VERIFY", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_GENERATED_HASH_FROM_PRF_SERVER_FINISHED", stream[3], 0)     
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_SEND_CERTIFICATE_VERIFY", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_CLIENT_FINISHED", stream[3], 0)            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_HASHED_CLIENT_FINISHED", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_HASHED_SERVER_FINISHED", stream[3], 0)            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_CERTIFICATE_REQUEST", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_SEND_CLIENT_KEYEXCHANGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_CLIENT_CERTIFICATE", stream[3], 0)            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_CERTIFICATE_VERIFY", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_INIT_SERVER_FINISHED", stream[3], 0)            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_CLIENT_HELLO", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_SERVER_HELLO", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_SERVER_CERTIFICATE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_SERVER_HELLO_DONE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_CLIENT_KEYEXCHANGE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_CLIENT_FINISHED", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_SERVER_FINISHED", stream[3], 0)            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVE_SIMPLE_MESSAGE", stream[3], 0)
            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_CERTIFICATE_REQUEST", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_CLIENT_CERTIFICATE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_CIPHER_SPEC", stream[3], 0 * 2)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_RECEIVED_CHANGE_CIPHER_SPEC", stream[3], 0)
            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_CLIENT_HELLO", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_SERVER_HELLO", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_SERVER_CERTIFICATE", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SEND_SERVER_HELLO_DONE", stream[3], 0)
            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SERVER_HELLO_DONE_VALIDATED_CERT", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SERVER_FINISHED_HASHED_COMPARISON_HASH", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SERVER_FINISHED_GENERATED_HASH_PRF", stream[3], 0)
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SERVER_AUTHENTICATED", stream[3], 0)
            
            General().add_to_three_dict(appearances_actual, "MonitorTags.CP_SESSION_AVAILABLE_SEND_MESSAGE", stream[3], 0)
            

        # count number of appearances
        print("Appearance count: ")
        sec = " " + self.arg_out
        with open(os.path.join(self.start_path, sec), 'rt') as csvfile:
            spamreader = csv.reader(csvfile, delimiter=';')
            for row in spamreader:
                if not row: continue
                
                if row[3] in appearances_actual:
                    if isinstance(appearances_actual[row[3]], dict):
                        appearances_actual[row[3]][row[6]] += 1

                    else:
                        appearances_actual[row[3]] += 1
                        
        # compare expected to actual number
        for tag in appearances_expected:
            
            if isinstance(appearances_actual[tag], dict):
                for kk in appearances_actual[tag]:        
                    if appearances_actual[tag][kk] != appearances_expected[tag][kk]:
                        print("%s, stream  %s: found %s appearances, expected %s" % (tag, kk, appearances_actual[tag][kk], appearances_expected[tag][kk]))
                        return False
            else:
                if appearances_actual[tag] != appearances_expected[tag]:
                    print("%s: found %s appearances, expected %s" % (tag, appearances_actual[tag], appearances_expected[tag]))
                    return False
                
        return True


    def _all_ecus(self, streams):
        ecus = []
        for stream in streams:
            if stream[0] not in ecus and not isinstance(stream[0], list):
                ecus.append(stream[0])
                
            for ecu in stream[1]:
                if ecu not in ecus:
                    ecus.append(ecu)
        return ecus
                
    def _get_expected_sync_msgs(self, streams):
    
        all_ecus = self._all_ecus(streams)
        nr_sync_messages = 0
        for ecu in all_ecus:
            nr_sync_messages += len(self._senders_to_sync(ecu, streams))
        return nr_sync_messages
        
    def _get_number_receivers_map(self, streams):
        da_map = {}
        for stream in streams:
            da_map[stream[3]] = len(eval(str(stream))[1])
        return da_map
        
    def _senders_to_sync(self, ecu_id, streams):
        ''' determine all senders that this ecu has to sync with. So all
            stream senders where this ecu is the receiver
             
            Input:    -
            Output:   synchronization_ids    list     list of sender ids with which this ecu will synchronize
        '''
        synchronization_ids = []
        for stream in streams:
            if ecu_id in stream[1] and stream[0] not in synchronization_ids:
                synchronization_ids.append(stream[0])
        return synchronization_ids
    
if __name__ == "__main__":
    a = CSVRunLWATest(None)
    a.test_LWA_record()

