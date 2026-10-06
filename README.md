# Code completed through Week 3

This is the subset of the full project that maps to Phase 1 (lab setup +
literature review) and Phase 2 (traffic generation & labelling) in the
timeline. It does not include the parser, detection rules, evaluation or
report — those are Phase 3 onward and were only prototyped early; ask if you
want that code too.

## Files
- `src/generate_synthetic_pcaps.py` — writes a labelled synthetic PCAP dataset
  (9 files: benign x2, port scan, SSH brute-force, ARP spoofing, SYN flood,
  exfiltration, Telnet, weak TLS) and `data/labels.csv` with the ground truth.
  Used to develop and test the pipeline before real captures are ready;
  nothing is sent on any network.
- `src/crypto_utils.py` — the integrity half of the cryptography layer: SHA-256
  hashing of each PCAP and an Ed25519-signed manifest (the rest — the
  hash-chained alert log and AES-256-GCM encryption — belongs to the
  detection/storage stages, Phase 3+).

## Run it
```
pip install -r requirements.txt
python src/generate_synthetic_pcaps.py data
python src/crypto_utils.py sign data/pcaps keys data/manifest
python src/crypto_utils.py verify data/pcaps keys data/manifest
```
`data/pcaps/` and `data/labels.csv` are already generated here as a sample
of the expected output.

## Replacing with your real captures
Put your team's real PCAPs from the isolated VM lab into `data/pcaps/`
(overwrite the synthetic ones) and add one row per file to `data/labels.csv`:
`pcap_file,attack_type,attacker_ip,victim_ip,start_ts,end_ts`. Then re-run
the `sign`/`verify` commands above.
