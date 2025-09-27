import argparse
import statistics
import time

from charm.toolbox.pairinggroup import PairingGroup

from .ibpre_scheme import CollusionResistantIBPRE
from .utils import print_table, generate_random_message, measure_size


def _component_size(component, group):
    if isinstance(component, bytes):
        return max(1, len(component))
    if isinstance(component, int):
        return max(1, (component.bit_length() + 7) // 8)
    return measure_size(component, group)


def _ciphertext_size(ct, group):
    return (
        _component_size(ct['C1'], group)
        + _component_size(ct['C2'], group)
        + _component_size(ct['C3'], group)
        + _component_size(ct['C4'], group)
        + _component_size(ct['C5'], group)
    )


def _reencrypted_size(ct, group):
    return (
        _component_size(ct['D1'], group)
        + _component_size(ct['D2'], group)
        + _component_size(ct['D3'], group)
        + _component_size(ct['D4'], group)
        + _component_size(ct['D5'], group)
    )


DEFAULT_MESSAGE_BITS = [16, 32, 64, 128, 256]


def run_message_size_experiment(num_trials: int, message_bits_list):
    curve = 'SS512'
    try:
        group = PairingGroup(curve)
    except Exception:
        print(f"Curve {curve} is not supported in this environment.")
        return {}

    scheme = CollusionResistantIBPRE(group)
    id_delegator = "alice@example.com"
    id_delegatee = "bob@example.com"

    results = {}

    print(f"\nRunning message-size experiment on curve {curve} with {num_trials} trials per payload...")

    setup_start = time.time()
    msk, params = scheme.setup()
    setup_time = time.time() - setup_start

    key_start = time.time()
    sk_alice = scheme.keyGen(msk, id_delegator, params)
    sk_bob = scheme.keyGen(msk, id_delegatee, params)
    keygen_time = time.time() - key_start

    rk_start = time.time()
    rekey = scheme.rkGen(sk_alice, id_delegator, id_delegatee, params)
    rekey_time = time.time() - rk_start

    for bits in message_bits_list:
        byte_len = max(1, bits // 8)
        timings = {'encrypt': [], 'decrypt': [], 'reencrypt': [], 'redecrypt': []}
        sizes = {'ciphertext': [], 'reencrypted': []}
        failures = {'decrypt': 0, 'redecrypt': 0}

        for _ in range(num_trials):
            message = generate_random_message(length=byte_len)

            t0 = time.time()
            ciphertext = scheme.encrypt(message, id_delegator, params)
            timings['encrypt'].append(time.time() - t0)
            sizes['ciphertext'].append(_ciphertext_size(ciphertext, group))

            t0 = time.time()
            decrypted = scheme.decrypt(ciphertext, sk_alice, id_delegator, params)
            timings['decrypt'].append(time.time() - t0)
            if decrypted.decode('utf-8') != message:
                failures['decrypt'] += 1

            t0 = time.time()
            reenc = scheme.reEncrypt(ciphertext, rekey, id_delegator, params)
            timings['reencrypt'].append(time.time() - t0)
            sizes['reencrypted'].append(_reencrypted_size(reenc, group))

            t0 = time.time()
            redecrypted = scheme.reDecrypt(reenc, sk_bob, id_delegator, id_delegatee, params)
            timings['redecrypt'].append(time.time() - t0)
            if redecrypted.decode('utf-8') != message:
                failures['redecrypt'] += 1

        results[bits] = {
            'timings_ms': {k: statistics.mean(v) * 1000 for k, v in timings.items()},
            'sizes_bytes': {k: statistics.mean(v) for k, v in sizes.items()},
            'failures': failures,
        }

    return {
        'curve': curve,
        'num_trials': num_trials,
        'setup_time_ms': setup_time * 1000,
        'keygen_time_ms': keygen_time * 1000,
        'rekey_time_ms': rekey_time * 1000,
        'message_results': results,
    }


def summarise(results):
    if not results:
        print("No data collected.")
        return

    curve = results['curve']
    print(f"\nCurve: {curve}")
    print(f"Setup: {results['setup_time_ms']:.2f} ms | KeyGen: {results['keygen_time_ms']:.2f} ms | ReKeyGen: {results['rekey_time_ms']:.2f} ms")

    headers = ["Message bits", "Enc (ms)", "Dec (ms)", "ReEnc (ms)", "ReDec (ms)", "CT (bytes)", "ReCT (bytes)"]
    rows = []
    for bits, data in sorted(results['message_results'].items()):
        timings = data['timings_ms']
        sizes = data['sizes_bytes']
        rows.append([
            bits,
            f"{timings['encrypt']:.3f}",
            f"{timings['decrypt']:.3f}",
            f"{timings['reencrypt']:.3f}",
            f"{timings['redecrypt']:.3f}",
            f"{sizes['ciphertext']:.1f}",
            f"{sizes['reencrypted']:.1f}",
        ])

    print_table(headers, rows, "Message Size Experiment")


def parse_args():
    parser = argparse.ArgumentParser(description="Paul et al. IB-PRE message-size experiment")
    parser.add_argument('--trials', type=int, default=100, help='Trials per message size')
    parser.add_argument('--message-bits', type=int, nargs='*', default=DEFAULT_MESSAGE_BITS,
                        help='Message sizes (in bits) to benchmark')
    return parser.parse_args()


def main():
    args = parse_args()
    results = run_message_size_experiment(args.trials, args.message_bits)
    summarise(results)


if __name__ == "__main__":
    main()
