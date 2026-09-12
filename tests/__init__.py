"""Test suite for guardrail-monitor.

Layout mirrors how you should run it:

    tests/smoke/       Fast, no side effects. Does the shipped configuration
                       load, do the modules import, do the probe suite and the
                       policy files still agree. Run before every release.
    tests/unit/        Pure logic, one module each. No network, no subprocess.
    tests/functional/  Multiple components together, and real syscalls --
                       sockets, named pipes, subprocess exec, connect().

Run with `python run_tests.py` from the repo root (adds coverage), or with
plain `python -m unittest discover tests` / `pytest tests` if you prefer.
"""
