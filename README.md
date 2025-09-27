## Build the Docker Image

From the repository root for the bilinear scheme:

```
docker build -t paulbilinear-app .
```

On Apple Silicon hosts add `--platform linux/amd64` to avoid emulation warnings.

---

## Run the Experimental Harness

The container executes `PaulBilinear/src/main.py` by default, benchmarking the
Paul et al. IB-PRE construction on a symmetric pairing curve (`SS512`). If Charm’s
runtime is missing `.param` files, the code falls back to the strings bundled in
`src/params.py`, so the curve works out of the box. You can inspect curve support via:

```
docker run --rm --entrypoint python paulbilinear-app - <<'PY'
from charm.toolbox.pairinggroup import PairingGroup
for name in ['SS1536', 'BN256', 'SS512']:
    try:
        grp = PairingGroup(name)
    except Exception:
        print(f"{name}: unavailable")
        continue
    level = getattr(grp, 'securityLevel', lambda: 'n/a')()
    print(f"{name}: security ≈ {level} bits")
PY
```

Then launch the harness (curves below 128 bits are skipped automatically):

```
docker run --rm paulbilinear-app
```

Append CLI options from `main.py` as needed, e.g. `--trials 50` (the default is 100 trials).

---

## Run the Test Suite

Execute the unit tests (message-size and parameter-variation suites) inside
Docker:

```
docker run --rm --entrypoint python paulbilinear-app -m pytest tests
```

or, from a local environment with Charm installed:

```
python -m pytest tests
```

The tests cover correctness of the Paul et al. scheme over multiple message
lengths, re-encryption flows, and curve selections satisfying 128-bit security.
