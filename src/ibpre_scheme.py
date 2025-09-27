from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.core.engine.util import objectToBytes
import hashlib
import base64


def _b64(element, group):
    return base64.b64encode(objectToBytes(element, group)).decode('ascii')

class CollusionResistantIBPRE:
    def __init__(self, group_obj: PairingGroup):
        self.group = group_obj
        if hasattr(self.group, 'securityLevel') and self.group.securityLevel() < 128:
            raise ValueError("Selected pairing curve does not meet 128-bit security")

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
            'H2': lambda sigma, msg_bytes: self.group.hash((sigma, msg_bytes), ZR),
            'H3': lambda sigma, length: self._hash_bytes(sigma, length),
            'H4': lambda x: self.group.hash(x.encode('utf-8'), G1),
            'H5': lambda args: self.group.hash(args, ZR)
        }
        return (s, params)

    def _hash_bytes(self, element, output_len):
        material = objectToBytes(element, self.group)
        digest = b''
        counter = 0
        while len(digest) < output_len:
            counter_bytes = counter.to_bytes(4, 'big')
            digest += hashlib.sha256(material + counter_bytes).digest()
            counter += 1
        return digest[:output_len]

    @staticmethod
    def _xor_bytes(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def _hash_input(self, identity, C1, C2, C3, C4):
        parts = [identity, _b64(C1, self.group), _b64(C2, self.group),
                 _b64(C3, self.group), C4.hex()]
        return "||".join(parts)

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
        m_bytes = m.encode('utf-8')
        if not m_bytes:
            raise ValueError("Message must be non-empty")

        sigma = self.group.random(GT)
        r = params['H2'](sigma, m_bytes)
        
        C1 = params['g'] ** r
        C2 = params['g1'] ** r
        C3 = sigma * params['e'](params['Ppub2'], params['H1'](id_i) ** r)
        
        mask = params['H3'](sigma, len(m_bytes))
        C4 = self._xor_bytes(m_bytes, mask)
        
        hash_input = self._hash_input(id_i, C1, C2, C3, C4)
        C5 = params['H4'](hash_input) ** r
        
        return {'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5}

    def decrypt(self, C, skid_i, id_i, params):
        C1, C2, C3, C4, C5 = C['C1'], C['C2'], C['C3'], C['C4'], C['C5']
        
        hash_input = self._hash_input(id_i, C1, C2, C3, C4)
        if params['e'](C1, params['g1']) != params['e'](params['g'], C2) or \
           params['e'](C1, params['H4'](hash_input)) != params['e'](params['g'], C5):
            return b"INVALID CIPHERTEXT"
            
        sigma = C3 / params['e'](C2, skid_i)
        mask = params['H3'](sigma, len(C4))
        m_bytes = self._xor_bytes(C4, mask)

        if C2 != params['g1'] ** params['H2'](sigma, m_bytes):
            return b"INVALID CIPHERTEXT"
            
        return m_bytes

    def reEncrypt(self, C, RK_i_j, id_i, params):
        C1, C2, C3, C4, C5 = C['C1'], C['C2'], C['C3'], C['C4'], C['C5']
        hash_input = self._hash_input(id_i, C1, C2, C3, C4)
        
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
        mask = params['H3'](sigma, len(D4))
        m_bytes = self._xor_bytes(D4, mask)

        if D1 != params['g'] ** params['H2'](sigma, m_bytes):
            return b"INVALID CIPHERTEXT"
            
        return m_bytes
