"""Offline recovery ordering, lost-write uncertainty and no automatic retry."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tsa_reset_evidence import RecoveryTrace

def reply(trace, text):
    trace.record_routine_reply(bytes.fromhex(text))

def rejects(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('Out-of-sequence operation accepted')

def completed():
    t = RecoveryTrace()
    t.record_attempt()
    reply(t, '7F 31 78')
    assert t.stage == 'awaiting_start_reply'
    reply(t, '71 01 70 14')
    reply(t, '71 03 70 14 80')
    reply(t, '7F 31 78')
    assert t.stage == 'awaiting_completion'
    reply(t, '71 03 70 14 62')
    assert t.stage == 'awaiting_not_adapted'
    return t

not_adapted = bytes.fromhex('62 03 02 00 00')
adapted = bytes.fromhex('62 03 02 00 FF')
t = completed()
rejects(t.record_attempt)
t.record_adaptation_reply(not_adapted)
t.record_adaptation_reply(not_adapted)
assert t.stage == 'awaiting_adapted'
t.record_adaptation_reply(adapted)
for value in (-1, 0, 59.9, float('nan'), float('inf'), True):
    rejects(lambda: t.record_power_cycle(off_seconds=value))
assert t.stage == 'awaiting_power_cycle'
t.record_power_cycle(off_seconds=60)
t.record_adaptation_reply(adapted)
assert t.stage == 'persistence_observed'
t.record_returning_faults(['P1702'])
assert t.returning_faults == ('P1702',)
assert t.stage == 'persistence_observed'  # adaptation evidence != fault-free TSA
rejects(t.record_attempt)

for payload in ('71 03 70 14 64', '7F 31 33', '71 02 70 14'):
    t = RecoveryTrace()
    t.record_attempt()
    reply(t, payload)
    assert t.stage == 'failed'
    rejects(t.record_attempt)

for payload in ('', '71 03 70 14 62', '71 01 70 14 00'):
    t = RecoveryTrace()
    t.record_attempt()
    reply(t, payload)
    assert t.stage == 'uncertain'
    rejects(t.record_attempt)

for after_ack in (False, True):
    t = RecoveryTrace()
    t.record_attempt()
    if after_ack:
        reply(t, '71 01 70 14')
    t.record_interruption()
    assert t.stage == 'uncertain'
    rejects(t.record_attempt)
    rejects(lambda: reply(t, '71 03 70 14 62'))

for payload in (adapted, bytes.fromhex('62 03 02 00 AA'), b'', not_adapted + b'\x00'):
    t = completed()
    t.record_adaptation_reply(payload)
    assert t.stage == 'uncertain'

t = completed()
t.record_adaptation_reply(not_adapted)
t.record_adaptation_reply(adapted)
t.record_power_cycle(off_seconds=61)
t.record_adaptation_reply(not_adapted)
assert t.stage == 'failed'
rejects(t.record_attempt)
print('Recovery ordering, persistence readback, returning faults and lost-write uncertainty passed')
