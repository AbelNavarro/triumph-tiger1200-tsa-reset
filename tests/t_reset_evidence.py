"""Offline response semantics; never imports the live transport."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tsa_reset_evidence import interpret_30174_result

cases = {
    '71017014': 'accepted', '71027014': 'stopped',
    '7103701480': 'pending', '7103701462': 'completed',
    '7103701464': 'stopped_or_error', '7F3178': 'response_pending',
    '7F3133': 'rejected', '7F3122': 'rejected', '7F3124': 'rejected',
    '': 'unknown', '71037014': 'unknown', '7103701400': 'unknown',
    '710370146200': 'unknown', '7101701462': 'unknown',
    '7103701562': 'unknown', '7F1978': 'unknown',
}
for raw, expected in cases.items():
    assert interpret_30174_result(bytes.fromhex(raw)).kind == expected, raw
for raw in ('71017014', '7103701480', '7103701464', '', '7F3178'):
    assert interpret_30174_result(bytes.fromhex(raw)).kind != 'completed'
assert 'unverified' in interpret_30174_result(bytes.fromhex('7103701462')).explanation
print('16 response cases passed; no transport imported')
