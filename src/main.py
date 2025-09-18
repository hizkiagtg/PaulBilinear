import time
from charm.toolbox.pairinggroup import PairingGroup

# Local application imports
from .ibpre_scheme import CollusionResistantIBPRE
from .utils import print_table, generate_random_message, measure_size

def tune_bilinear_parameters(num_trials=10):
    """Tests various pairing curve types for the bilinear scheme."""
    curve_types = ['SS512'] 
    results = {}
    id_delegator = "alice@example.com"
    id_delegatee = "bob@example.com"

    for curve in curve_types:
        group = PairingGroup(curve)
        ibpre = CollusionResistantIBPRE(group)

        times = {'setup': 0, 'keygen': 0, 'rkgen': 0, 'encrypt': 0,
                 'reencrypt': 0, 'decrypt': 0, 'redecrypt': 0}
        
        print(f"\nRunning {num_trials} trials for curve: {curve}...")
        for _ in range(num_trials):
            message = generate_random_message(length=2)
            
            start = time.time()
            msk, params = ibpre.setup()
            times['setup'] += time.time() - start

            start = time.time()
            sk_alice = ibpre.keyGen(msk, id_delegator, params)
            sk_bob = ibpre.keyGen(msk, id_delegatee, params)
            times['keygen'] += time.time() - start

            start = time.time()
            rk = ibpre.rkGen(sk_alice, id_delegator, id_delegatee, params)
            times['rkgen'] += time.time() - start

            start = time.time()
            ciphertext = ibpre.encrypt(message, id_delegator, params)
            times['encrypt'] += time.time() - start

            start = time.time()
            reencrypted = ibpre.reEncrypt(ciphertext, rk, id_delegator, params)
            times['reencrypt'] += time.time() - start

            start = time.time()
            decrypted = ibpre.decrypt(ciphertext, sk_alice, id_delegator, params)
            times['decrypt'] += time.time() - start

            start = time.time()
            redecrypted = ibpre.reDecrypt(reencrypted, sk_bob, id_delegator, id_delegatee, params)
            times['redecrypt'] += time.time() - start

            if decrypted != message.encode('utf-8') or redecrypted != message.encode('utf-8'):
                print(f"ERROR: Decryption failed for curve {curve}")
                break

        # Calculate averages
        avg_times = {k: (v / num_trials) * 1000 for k, v in times.items()}
        results[curve] = avg_times
    
    # Print final results table
    headers = ["Operation"] + list(results.keys())
    ops = list(next(iter(results.values())).keys())
    rows = []
    for op in ops:
        row = [op] + [f"{results[curve][op]:.2f}" for curve in results.keys()]
        rows.append(row)
    print_table(headers, rows, "Average Execution Time (ms) per Curve Type")

if __name__ == "__main__":
    tune_bilinear_parameters()