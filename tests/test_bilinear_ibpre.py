import pytest

from charm.toolbox.pairinggroup import PairingGroup

from src.ibpre_scheme import CollusionResistantIBPRE
from src.utils import generate_random_message


@pytest.fixture(scope="module")
def group():
    try:
        return PairingGroup('SS512')
    except Exception:
        pytest.skip("SS512 pairing unavailable")
@pytest.fixture(scope="module")
def scheme(group):
    return CollusionResistantIBPRE(group)


@pytest.fixture(scope="module")
def system_params(scheme):
    msk, params = scheme.setup()
    return msk, params


@pytest.mark.parametrize("length", [2, 16])
def test_encrypt_decrypt_various_lengths(scheme, system_params, length):
    msk, params = system_params
    identity = "alice@example.com"
    message = generate_random_message(length)
    sk = scheme.keyGen(msk, identity, params)

    ciphertext = scheme.encrypt(message, identity, params)
    plaintext = scheme.decrypt(ciphertext, sk, identity, params)

    assert plaintext.decode('utf-8') == message


def test_reencryption_roundtrip(scheme, system_params):
    msk, params = system_params
    delegator = "alice@example.com"
    delegatee = "bob@example.com"
    message = "proxy-test"

    sk_delegator = scheme.keyGen(msk, delegator, params)
    sk_delegatee = scheme.keyGen(msk, delegatee, params)
    ciphertext = scheme.encrypt(message, delegator, params)
    rekey = scheme.rkGen(sk_delegator, delegator, delegatee, params)
    transformed = scheme.reEncrypt(ciphertext, rekey, delegator, params)

    assert scheme.decrypt(ciphertext, sk_delegator, delegator, params).decode('utf-8') == message
    assert scheme.reDecrypt(transformed, sk_delegatee, delegator, delegatee, params).decode('utf-8') == message


def test_invalid_ciphertext_detection(scheme, system_params):
    msk, params = system_params
    identity = "alice@example.com"
    sk = scheme.keyGen(msk, identity, params)
    ciphertext = scheme.encrypt("tamper", identity, params)

    corrupted = dict(ciphertext)
    corrupted['C4'] = b'\x00' + ciphertext['C4'][1:]
    assert scheme.decrypt(corrupted, sk, identity, params) == b"INVALID CIPHERTEXT"


def test_rekey_generation_and_use(scheme, system_params):
    msk, params = system_params
    delegator = "alice@example.com"
    delegatee = "bob@example.com"
    message = "level80"

    sk_i = scheme.keyGen(msk, delegator, params)
    sk_j = scheme.keyGen(msk, delegatee, params)
    rk = scheme.rkGen(sk_i, delegator, delegatee, params)

    expected_xij = params['H5']((rk['e1'], delegator, delegatee))
    assert rk['xij'] == expected_xij

    ct = scheme.encrypt(message, delegator, params)
    assert scheme.decrypt(ct, sk_i, delegator, params).decode('utf-8') == message

    transformed = scheme.reEncrypt(ct, rk, delegator, params)
    assert scheme.reDecrypt(transformed, sk_j, delegator, delegatee, params).decode('utf-8') == message
