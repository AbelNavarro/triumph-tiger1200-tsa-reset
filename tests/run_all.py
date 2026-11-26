"""Run the complete offline test suite. No adapter or motorcycle needed.

    python tests/run_all.py

Each tests/t_*.py runs in its own isolated interpreter (they stub pyserial
and patch module globals). Exit code is non-zero if any test fails.
"""
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent


def main():
    tests = sorted(HERE.glob("t_*.py"))
    failed = []
    for t in tests:
        start = time.time()
        p = subprocess.run([sys.executable, "-I", str(t)], cwd=str(HERE.parent),
                           capture_output=True, text=True, timeout=600)
        ok = p.returncode == 0
        last = (p.stdout.strip().splitlines() or [""])[-1]
        print(f"{'PASS' if ok else 'FAIL'}  {t.name:24} {time.time() - start:5.1f}s  {last}")
        if not ok:
            failed.append(t.name)
            print("      " + (p.stdout + p.stderr).strip().replace("\n", "\n      ")[-3000:])
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
