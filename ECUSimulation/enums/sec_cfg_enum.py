'''
Created on 17 Mar, 2015

@author: artur.mrowca
'''
from enum import Enum
from tools.singleton import Singleton

class PRF(Enum):
    DUMMY = 0
    DUMMY_SHA = 1

class AuKeyLengthEnum(Enum):
    bit_128 = 0   
    bit_192 = 1
    bit_256 = 2
    bit_384 = 3
    bit_521 = 4
    bit_512 = 5
    bit_1024 = 6
    bit_2048 = 7

class HashMechEnum(Enum):
    MD5 = 8
    SHA1 = 9
    SHA256 = 10
    
class SymAuthMechEnum(Enum):
    AES = 11
    CBC = 30
    CTR = 31
    CCM = 32
    ECB = 33
    CMAC = 34


class AsymAuthMechEnum(Enum):
    RSA = 12
    ECC = 13   
    
class CAEnum(Enum):
    ROOT = 14
    
    CA_L1 = 15
    CA_L2 = 16
    CA_L3 = 17
    
    CA_L11 = 18
    CA_L12 = 19
    CA_L13 = 20
    
    CA_L21 = 21
    CA_L22 = 22
    CA_L23 = 23
    
    CA_L31 = 24
    CA_L32 = 25
    CA_L33 = 26

    CA_L311 = 27
    CA_L312 = 28
    CA_L313 = 29
    
class UserIDEnum(Enum):
    ECU_STD = 30
    SEC_MOD = 31
    

class EnumTrafor(Singleton):
    ''' transforms enums to values'''
    
    def to_enum(self, strin):
        
        if strin == "RSA": return AsymAuthMechEnum.RSA
        if strin == "ECC": return AsymAuthMechEnum.ECC
        
        if strin == "AES": return SymAuthMechEnum.AES
        if strin == "CBC": return SymAuthMechEnum.CBC
        if strin == "CTR": return SymAuthMechEnum.CTR
        if strin == "CCM": return SymAuthMechEnum.CCM
        if strin == "ECB": return SymAuthMechEnum.ECB
        if strin == "CMAC": return SymAuthMechEnum.CMAC
        
        if strin == 128: return AuKeyLengthEnum.bit_128
        if strin == 192: return AuKeyLengthEnum.bit_192
        if strin == 256: return AuKeyLengthEnum.bit_256
        if strin == 384: return AuKeyLengthEnum.bit_384
        if strin == 512: return AuKeyLengthEnum.bit_512
        if strin == 521: return AuKeyLengthEnum.bit_521
        if strin == 1024: return AuKeyLengthEnum.bit_1024
        if strin == 2048: return AuKeyLengthEnum.bit_2048

        if strin == 'MD5': return HashMechEnum.MD5
        if strin == 'SHA1': return HashMechEnum.SHA1
        if strin == 'SHA256': return HashMechEnum.SHA256
    
    def to_value(self, enum):
        if enum == AuKeyLengthEnum.bit_128: return 128
        if enum == AuKeyLengthEnum.bit_192: return 192
        if enum == AuKeyLengthEnum.bit_256: return 256
        if enum == AuKeyLengthEnum.bit_384: return 384
        if enum == AuKeyLengthEnum.bit_512: return 512
        if enum == AuKeyLengthEnum.bit_521: return 521
        if enum == AuKeyLengthEnum.bit_1024: return 1024
        if enum == AuKeyLengthEnum.bit_2048: return 2048        
        
        
        if enum == SymAuthMechEnum.CBC: return "CBC"
        if enum == SymAuthMechEnum.CTR: return "CTR"
        if enum == SymAuthMechEnum.CCM: return "CCM"
        if enum == SymAuthMechEnum.ECB: return "ECB"
        if enum == SymAuthMechEnum.CMAC: return "CMAC"
        
        if enum == HashMechEnum.MD5: return 'MD5'
        if enum == HashMechEnum.SHA1: return 'SHA1'
        if enum == HashMechEnum.SHA256: return 'SHA256'
        
        if enum == SymAuthMechEnum.AES: return 'AES'
        
        if enum == AsymAuthMechEnum.RSA: return 'RSA'
        if enum == AsymAuthMechEnum.ECC: return 'ECC'
    
        return  enum
            
            
    
    
    
