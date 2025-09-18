from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.core.math.integer import integer, int2Bytes
from charm.core.engine.util import objectToBytes
import hashlib

class CollusionResistantIBPRE:
    def __init__(self, group_obj: PairingGroup):
        self.group = group_obj
        self.n = self.group.messageSize()  # Length of messages in bits
        self.message_space = 1 << self.n

    def setup(self):
        g = self.group.random(G1)
        h_val = self.group.random(G1)
        s = self.group.random(ZR)
        g1 = g ** s
        Ppub2 = g ** (s * s)
        
        params = {
            'g': g, 'h': h_val, 'g1': g1, 'h1': h_val ** s,
            'Ppub1': g1, 'Ppub2': Ppub2, 'e': pair,
            'H1': lambda x: self.group.hash(x.encode('utf-8'), G1),
            'H2': lambda x, y: self.group.hash((x, y), ZR),
            'H3': lambda x: self._hash_to_n_bits(x, self.n),
            'H4': lambda x: self.group.hash(x.encode('utf-8'), G1),
            'H5': lambda args: self.group.hash(args, ZR)
        }
        return (s, params)

    def _hash_to_n_bits(self, element, n):
        element_bytes = objectToBytes(element, self.group)
        hash_obj = hashlib.sha256(element_bytes)
        # Reduce the hash to n bits
        return int.from_bytes(hash_obj.digest(), byteorder='big') % (1 << n)

    def _int_to_bytes(self, value, length):
        return value.to_bytes((length + 7) // 8, byteorder='big')

    def keyGen(self, msk, id_i, params):
        return params['H1'](id_i) ** msk

    def rkGen(self, skid_i, id_i, id_j, params):
        s1, s2 = self.group.random(ZR), self.group.random(ZR)
        e1 = params['e'](params['Ppub1'], params['H1'](id_j) ** s1)
        xij = params['H5']((e1, id_i, id_j))
        
        RK1 = (skid_i ** -1) * (params['h'] ** (xij * s2))
        RK2 = params['h1'] ** s2
        RK3 = params['g'] ** s1
        
        return {'RK1': RK1, 'RK2': RK2, 'RK3': RK3, 'e1': e1, 'xij': xij}

    def encrypt(self, m, id_i, params):
        enc_m = int.from_bytes(m.encode('utf-8'), byteorder='big')
        if not (0 <= enc_m < self.message_space):
            raise ValueError("Message is out of the valid message space.")
            
        sigma = self.group.random(GT)
        r = params['H2'](sigma, self._int_to_bytes(enc_m, self.n))
        
        C1 = params['g'] ** r
        C2 = params['g1'] ** r
        C3 = sigma * params['e'](params['Ppub2'], params['H1'](id_i) ** r)
        
        h3_sigma = params['H3'](sigma)
        C4 = enc_m ^ h3_sigma
        
        hash_input = f"{id_i}||{C1}||{C2}||{C3}||{C4}"
        C5 = params['H4'](hash_input) ** r
        
        return {'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5}

    def decrypt(self, C, skid_i, id_i, params):
        C1, C2, C3, C4, C5 = C['C1'], C['C2'], C['C3'], C['C4'], C['C5']
        
        hash_input = f"{id_i}||{C1}||{C2}||{C3}||{C4}"
        if params['e'](C1, params['g1']) != params['e'](params['g'], C2) or \
           params['e'](C1, params['H4'](hash_input)) != params['e'](params['g'], C5):
            return b"INVALID CIPHERTEXT"
            
        sigma = C3 / params['e'](C2, skid_i)
        h3_sigma = params['H3'](sigma)
        m_int = C4 ^ h3_sigma
        m_bytes = self._int_to_bytes(m_int, self.n)
        
        if C2 != params['g1'] ** params['H2'](sigma, m_bytes):
            return b"INVALID CIPHERTEXT"
            
        return int2Bytes(integer(m_int))

    def reEncrypt(self, C, RK_i_j, id_i, params):
        C1, C2, C3, C4, C5 = C['C1'], C['C2'], C['C3'], C['C4'], C['C5']
        hash_input = f"{id_i}||{C1}||{C2}||{C3}||{C4}"
        
        if params['e'](C1, params['H4'](hash_input)) != params['e'](params['g'], C5):
            return "INVALID CIPHERTEXT"
            
        D3 = C3 * params['e'](C2, RK_i_j['RK1'])
        return {
            'D1': C1, 'D2': RK_i_j['RK3'], 'D3': D3,
            'D4': C4, 'D5': RK_i_j['RK2'], 'e1': RK_i_j['e1'],
            'xij': RK_i_j['xij']
        }

    def reDecrypt(self, D, skid_j, id_i, id_j, params):
        D1, D3, D4, D5 = D['D1'], D['D3'], D['D4'], D['D5']
        
        xij_computed = params['H5']((D['e1'], id_i, id_j))
        if D['xij'] != xij_computed:
            return b"INVALID RE-ENCRYPTION KEY"
            
        sigma = D3 / params['e'](D1, D5 ** D['xij'])
        h3_sigma = params['H3'](sigma)
        m_int = D4 ^ h3_sigma
        m_bytes = self._int_to_bytes(m_int, self.n)
        
        if D1 != params['g'] ** params['H2'](sigma, m_bytes):
            return b"INVALID CIPHERTEXT"
            
        return int2Bytes(integer(m_int))