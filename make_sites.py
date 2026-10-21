"""Generate synthetic site CSV files for the MedMesh demo.

Site A: 120 patients
Site B: 80 patients
Site C: 60 patients

Columns: id, name, age, sex, bmi, diagnosis
Diagnoses: flu, covid, asthma, diabetes, rare
Exactly 2 rare patients per site.
All non-rare diagnosis groups and sex groups have at least 5 patients per site.
Fixed random seed: 7.
"""

import csv
import random
from pathlib import Path

SEED = 7
DIAGNOSES = ["flu", "covid", "asthma", "diabetes"]
SEXES = ["M", "F"]
SITES = [
    ("site_a.csv", 120),
    ("site_b.csv", 80),
    ("site_c.csv", 60),
]

# Minimum patients per non-rare diagnosis and per sex group.
MIN_GROUP = 5
# Exactly 2 rare patients per site.
RARE_COUNT = 2


def make_patients(count, site_index, rng):
    """Return a list of patient dicts for one site."""
    patients = []
    pid = site_index * 10000 + 1

    # Build a balanced base: MIN_GROUP per (sex x diagnosis) cell.
    # That gives 2 sex x 4 diagnoses x MIN_GROUP = 40 base patients.
    base = []
    for sex in SEXES:
        for diag in DIAGNOSES:
            for _ in range(MIN_GROUP):
                base.append((sex, diag))

    # Shuffle the base.
    rng.shuffle(base)

    # Fill remaining slots with random combos.
    extra_count = count - RARE_COUNT - len(base)
    for _ in range(extra_count):
        sex = rng.choice(SEXES)
        diag = rng.choice(DIAGNOSES)
        base.append((sex, diag))

    rng.shuffle(base)

    for i, (sex, diag) in enumerate(base):
        name = f"Patient {pid:04d}"
        age = rng.randint(18, 90)
        bmi = round(rng.uniform(15.0, 45.0), 1)
        patients.append({
            "id": pid, "name": name, "age": age, "sex": sex,
            "bmi": bmi, "diagnosis": diag,
        })
        pid += 1

    # Add exactly 2 rare patients.
    for _ in range(RARE_COUNT):
        sex = rng.choice(SEXES)
        name = f"Patient {pid:04d}"
        age = rng.randint(18, 90)
        bmi = round(rng.uniform(15.0, 45.0), 1)
        patients.append({
            "id": pid, "name": name, "age": age, "sex": sex,
            "bmi": bmi, "diagnosis": "rare",
        })
        pid += 1

    rng.shuffle(patients)
    # Re-assign sequential IDs after shuffle.
    base_id = site_index * 10000 + 1
    for i, p in enumerate(patients):
        p["id"] = base_id + i

    return patients


def write_csv(path, patients):
    """Write patients to a CSV file."""
    fields = ["id", "name", "age", "sex", "bmi", "diagnosis"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(patients)


def main():
    rng = random.Random(SEED)
    out_dir = Path(__file__).parent
    for filename, count in SITES:
        site_index = SITES.index((filename, count))
        patients = make_patients(count, site_index, rng)
        path = out_dir / filename
        write_csv(path, patients)
        print(f"wrote {path.name}: {len(patients)} patients")


if __name__ == "__main__":
    main()
