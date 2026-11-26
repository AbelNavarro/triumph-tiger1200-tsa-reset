"""Offline interpretations of the researched 30174 image, never a write API.

Inputs are already reassembled UDS payloads, with source/request correlation
performed by the caller. These meanings do not identify the installed firmware.
No serial imports, requests, retries, or live reset integration exist here.
See FINDINGS.md and ECU-REFERENCE.md.
"""
from dataclasses import dataclass


class RecoveryTrace:
    """Offline, ordered evidence for ONE attempted reset; never sends requests.

    Caller must correlate payloads to the same ECU/attempt and establish the
    firmware match externally. This is not authorization to transmit. An
    uncertain exchange consumes the attempt: do not replay a lost write.
    A returning fault is reportable, not a reason to reset automatically.
    """

    def __init__(self):
        self.stage = 'not_attempted'
        self.returning_faults = ()

    def record_attempt(self):
        if self.stage != 'not_attempted':
            raise ValueError('This trace already contains a reset attempt; no retry.')
        self.stage = 'awaiting_start_reply'

    def record_routine_reply(self, payload: bytes):
        if self.stage not in ('awaiting_start_reply', 'awaiting_completion'):
            raise ValueError('Routine reply outside the active attempt.')
        kind = interpret_30174_result(payload).kind
        if kind == 'response_pending':
            return
        if self.stage == 'awaiting_start_reply' and kind == 'accepted':
            self.stage = 'awaiting_completion'
        elif self.stage == 'awaiting_completion' and kind == 'pending':
            return
        elif self.stage == 'awaiting_completion' and kind == 'completed':
            self.stage = 'awaiting_not_adapted'
        elif kind in ('rejected', 'stopped', 'stopped_or_error'):
            self.stage = 'failed'
        else:
            self.stage = 'uncertain'

    def record_interruption(self):
        """Lost response, cancellation, timeout or disconnect: no inferred success."""
        if self.stage in ('not_attempted', 'failed', 'uncertain', 'persistence_observed'):
            raise ValueError('No active recovery to interrupt.')
        self.stage = 'uncertain'

    def record_adaptation_reply(self, payload: bytes):
        """Full, reassembled DID0302 response; unknown values never advance."""
        if self.stage not in ('awaiting_not_adapted', 'awaiting_adapted',
                              'awaiting_power_cycle', 'awaiting_persistence'):
            raise ValueError('Adaptation readback is out of sequence.')
        if payload == bytes.fromhex('62 03 02 00 00'):
            if self.stage == 'awaiting_not_adapted':
                self.stage = 'awaiting_adapted'
            elif self.stage in ('awaiting_power_cycle', 'awaiting_persistence'):
                self.stage = 'failed'
        elif payload == bytes.fromhex('62 03 02 00 FF'):
            if self.stage == 'awaiting_adapted':
                self.stage = 'awaiting_power_cycle'
            elif self.stage == 'awaiting_persistence':
                self.stage = 'persistence_observed'
            elif self.stage == 'awaiting_not_adapted':
                self.stage = 'uncertain'  # reset readback was never observed
        else:
            self.stage = 'uncertain'

    def record_power_cycle(self, *, off_seconds: float):
        """Record externally confirmed OFF duration followed by ignition ON."""
        import math
        if self.stage != 'awaiting_power_cycle':
            raise ValueError('Relearning must be observed first.')
        if isinstance(off_seconds, bool) or not math.isfinite(off_seconds) or off_seconds < 60:
            raise ValueError('A confirmed ignition-off interval of at least 60 seconds is required.')
        self.stage = 'awaiting_persistence'

    def record_returning_faults(self, faults):
        # Preserve evidence without suppressing faults or restarting the reset.
        self.returning_faults = tuple(faults)


@dataclass(frozen=True)
class RoutineObservation:
    kind: str
    explanation: str


def interpret_30174_result(payload: bytes) -> RoutineObservation:
    """Interpret one exact response, without claiming reset/relearn success."""
    if payload == bytes.fromhex('71 01 70 14'):
        return RoutineObservation('accepted', 'Start acknowledged; completion unknown.')
    if payload == bytes.fromhex('71 02 70 14'):
        return RoutineObservation('stopped', 'Stop acknowledged; not successful completion.')
    if payload == bytes.fromhex('71 03 70 14 80'):
        return RoutineObservation('pending', 'Routine still active; do not resend start.')
    if payload == bytes.fromhex('71 03 70 14 62'):
        return RoutineObservation('completed',
            '30174 reports completion without its storage-processing error flag; '
            'state readback, relearning and persistence remain unverified.')
    if payload == bytes.fromhex('71 03 70 14 64'):
        return RoutineObservation('stopped_or_error',
            '30174 reports the stopped/error state; not successful completion.')
    if len(payload) == 3 and payload[:2] == bytes.fromhex('7F 31'):
        if payload[2] == 0x78:
            return RoutineObservation('response_pending',
                'UDS response pending; final routine response unknown.')
        return RoutineObservation('rejected', 'Routine negative response: %02X.' % payload[2])
    return RoutineObservation('unknown', 'No recognized complete 30174 routine response.')
