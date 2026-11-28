"""
CLI for masking / de-masking CSV and XLSX files.

  python mask_file.py mask   data.csv
  python mask_file.py unmask data.masked.csv
  python mask_file.py mask   scan.png      (OCR, irreversible)
"""
import argparse
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    p = argparse.ArgumentParser(description="GOVSHIELD file masking (CSV/XLSX/TXT, images and scanned PDF via OCR)")
    p.add_argument("action", choices=["mask", "unmask"])
    p.add_argument("input")
    p.add_argument("-o", "--output")
    p.add_argument("--map-file", help="encrypted mapping file (default: <masked>.map.enc)")
    p.add_argument("--key-file", help="encryption key file (default: <masked>.key)")
    p.add_argument("--header-row", type=int, default=1)
    p.add_argument("--col", action="append", default=[], metavar="HEADER=TYPE",
                   help="force a column type, e.g. --col \"الاسم=PERSON\" or --col \"Product Name=SKIP\"")
    p.add_argument("--no-ner", action="store_true",
                   help="disable HuggingFace NER models (much faster, dictionary + regex only)")
    a = p.parse_args()

    if a.no_ner:  # must be set BEFORE importing the engine
        os.environ["GOVSHIELD_NER_MODEL"] = "none"
        os.environ["GOVSHIELD_NER_MODEL_EN"] = "none"
    sys.path.insert(0, os.path.join(ROOT, "privacy-engine", "files"))
    from file_masker import mask_file, unmask_file

    stem, ext = os.path.splitext(a.input)
    if a.action == "mask":
        out = a.output or f"{stem}.masked{ext}"
        overrides = dict(c.rsplit("=", 1) for c in a.col)
        try:
            r = mask_file(a.input, out, a.map_file, a.key_file, a.header_row, overrides)
        except Exception as e:
            if type(e).__name__ == "OcrBlocked":
                sys.exit(f"BLOCKED: {e}. No output file was produced.")
            raise
        print(f"Masked file : {r['output']}")
        if r.get("reversible") is False:
            print("Image/scanned PDF: covered irreversibly (no mapping, nothing to restore)\n")
        else:
            print(f"Mapping     : {r['map_file']}  (encrypted)")
            print(f"Key         : {r['key_file']}")
            print(f"Unique tokens: {r['unique_tokens']}\n")
        print(f"{'SHEET':12} {'COLUMN':25} {'TYPE':10} COUNT")
        for k, n in sorted(r["stats"].items(), key=lambda x: str(x[0])):
            if len(k) == 3:
                print(f"{str(k[0]):12} {str(k[1]):25} {k[2]:10} {n}")
            else:
                print(f"{k[0]}: {n}")
        if r.get("reversible") is not False:
            print("\nWARNING: keep the key + mapping files private and NEVER upload them "
                  "with the masked file.")
    else:
        base = stem[:-7] if stem.endswith(".masked") else stem
        out = a.output or f"{base}.restored{ext}"
        r = unmask_file(a.input, out, a.map_file, a.key_file, a.header_row)
        print(f"Restored file: {r['output']}")
        for k, n in r["stats"].items():
            print(f"{k[0]}: {n}")


if __name__ == "__main__":
    main()
