# MedMesh

Privacy-preserving federated research analysis. Inspired by DataSHIELD.

Each institution runs a local query server. The server accepts only approved
statistical requests, refuses requests for individual records, and refuses
results that cover fewer than 5 patients. A client sends the same request to
several sites and combines the returned summaries. No individual record leaves
any site.

## Three commands to run the demo

```
python make_sites.py
python run_demo.py --check
python run_demo.py --short
```

`make_sites.py` generates three synthetic site CSV files (site_a, site_b, site_c).
`run_demo.py --check` confirms all ports are free, files exist, and tests pass.
`run_demo.py --short` runs the full 2-minute demo in under 90 seconds.

## What the server allows

- `count`
- `mean age`, `mean bmi`
- `mean age where diagnosis = flu` (any diagnosis with at least 5 patients)
- `mean bmi where age > N`, `mean bmi where age < N`
- `count by sex`

## What the server refuses

- Requests for rows or identifying fields: `get all records`, `get patient 4`, `show name and diagnosis`
- Results covering fewer than 5 patients: `mean age where diagnosis = rare`, `count by diagnosis`
- Queries too similar to an earlier allowed query (overlap guard, unless `--no-overlap-guard`)
- Missing or wrong API key
- Requests over the per-user rate limit

Allowed responses contain only aggregate statistics. They do not include
patient ids, names, or rows.

## What is protected

- Individual records never leave the institution server.
- Output-disclosure checks enforce a minimum group size of 5 patients.
- The overlap guard blocks differencing attacks that try to isolate one patient
  by submitting two nearly identical queries whose patient sets differ by fewer
  than 5 patients.
- Every request (allowed, denied, failed auth) is appended to a tamper-evident
  audit log. Each log entry includes a SHA-256 hash chained to the previous
  entry. `verify_log.py` detects any modification.
- API keys authenticate users. Each user has a per-minute request limit.

## Known limits

- Plain HTTP only. No encryption in transit.
- Synthetic data only. No real patient records are used or included.
- API keys are stored in a plain JSON file (keys.json). Rotate them manually.
- All sites are simulated on one machine. In a real deployment each institution
  would run its own server on its own infrastructure.
- The pairwise overlap guard does not stop three-query combinations. A
  researcher can query the total, then `age > N`, then `age < N` and subtract
  to learn the group with age equal to N. This is a known limitation documented
  in attack_demo.py scenario D.
- Collusion between two authenticated accounts is not detected. If two users
  share their query results, the guard does not see the combined information.

## Running individual components

Start one server:

```
python server.py --port 8000 --data site_a.csv --site-name site_a
```

Start an unguarded server (for the attack demo):

```
python server.py --port 8010 --data site_a.csv --site-name unguarded --no-overlap-guard
```

Send a query to one server:

```
python client.py "mean age" --key key_ana_secure_001
```

Send the same query to three sites and pool the results:

```
python client.py "mean age" --sites 8000 8001 8002 --key key_ana_secure_001
```

Verify an audit log:

```
python verify_log.py logs/site_a.jsonl
```

Run the attack demonstration (requires servers to be running):

```
python attack_demo.py
```

Run all tests:

```
python -m unittest
```

## Next steps

- Add TLS so requests are encrypted in transit.
- Move API key storage out of a plain file (use a secrets manager).
- Implement the three-query guard to block scenario D differencing.
- Add cross-account query tracking to detect collusion.
- Replace synthetic data with a real institutional dataset.
- Deploy each site on a separate machine with network isolation.

## Inspiration

This prototype is inspired by DataSHIELD, an open-source framework for
privacy-preserving federated analysis of sensitive research data.
MedMesh is a simplified demonstration prototype built for the
PCC-26 Cyber Innovation and Startup Challenge concept note. It does not
claim to replace DataSHIELD or to introduce a new analytical method.
