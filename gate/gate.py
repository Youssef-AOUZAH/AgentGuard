"""The gate (piece 3a): takes one command from the agent and decides, explains, and runs it or not.

Takes in a command string. Returns an `Outcome` (`gate/types.py`): the final verdict, the message
for the agent, and, when the command ran, what the executor saw.

The stages, in order, each timed:

1. **parse**: `tokenize` and `parse`. A `LexError` or `ParseError` is a `DENY` citing R1 with
   the diagnostic code; nothing after this runs on a command we could not parse.
2. **analyze**: the middle end, behind the `Analyzer` interface, returns the effects and a
   `Decision`. Until `compiler/resolve.py`, `effects.py` and `policy.py` exist, the gate runs with
   `PendingMiddleEnd`, which escalates everything, so nothing runs unapproved.
3. **classify**: only when the session has refused something before and the decision is not
   already `DENY`. The new command is compared with the most recent refusal; every label that
   fires adds a reason citing R9, and the decision is tightened to the label's verdict. A
   classifier failure tightens to `ESCALATE` rather than being ignored.
4. **approve**: an `ESCALATE` is put to the `Approver`. With none, it is refused.
5. **emit**: our canonical re-serialisation of the parsed command. An `EmitError` is a `DENY`
   citing R1. What runs is always this, never the agent's text.
6. **execute**: in the sandbox. Then the session is updated from what really happened.

Two invariants hold throughout. **No stage lowers a verdict**: every combination goes through
`Decision.tighten`, and the approver can only release an `ESCALATE`, never a `DENY`. **Every
failure refuses**: any exception from the analyzer is caught here and becomes a refusal with
`Outcome.error` set, because an exception path nobody wrote a verdict for is how a guard fails
open.

Deliberately not handled: ESCALATE timeouts and asynchronous approval, and the policy's own
treatment of backgrounded statements (a rule id for those is still owed; see the PR #3 review).
"""

from __future__ import annotations

import time
from collections.abc import Callable

from classifier.labels import input_for
from classifier.pipeline import RetryClassifier
from compiler.emit import EmitError, emit
from compiler.parser import parse_source
from compiler.syntax import LexError, ParseError, Script
from compiler.types import Decision, Effect, Reason, RuleId, SessionState, Verdict
from gate.message import INTERNAL_ERROR, render
from gate.session import Session
from gate.types import Analyzer, Approver, ExecResult, Executor, MessageLevel, Outcome


class PendingMiddleEnd:
    """Stands in for the resolver, effect analysis and policy engine until they exist.

    It returns no effects and `ESCALATE`, which is exactly what the policy returns when every rule
    abstains: a command we cannot analyse is a command we do not understand. With no approver,
    every command is therefore refused, and with one, a human sees every command.
    """

    def analyze(self, script: Script, state: SessionState) -> tuple[frozenset[Effect], Decision]:
        return frozenset(), Decision(Verdict.ESCALATE)


class Gate:
    def __init__(
        self,
        executor: Executor,
        state: SessionState,
        *,
        analyzer: Analyzer | None = None,
        classifier: RetryClassifier | None = None,
        approver: Approver | None = None,
        level: MessageLevel = MessageLevel.RULE,
    ) -> None:
        self.executor = executor
        self.session = Session(state)
        self.analyzer: Analyzer = analyzer or PendingMiddleEnd()
        self.classifier = classifier
        self.approver = approver
        self.level = level

    @property
    def state(self) -> SessionState:
        return self.session.state

    def submit(self, command: str) -> Outcome:
        timings: dict[str, float] = {}
        start = time.perf_counter()
        turn = self.session.turn
        try:
            outcome = self._submit(command, turn, timings)
        except Exception as exc:  # fail closed: see the module docstring
            self.session.record_failure()
            outcome = Outcome(
                turn=turn,
                command=command,
                verdict=Verdict.DENY,
                message=INTERNAL_ERROR,
                error=f"{type(exc).__name__}: {exc}",
                timings=timings,
            )
        timings["total"] = time.perf_counter() - start
        return outcome

    def _submit(self, command: str, turn: int, timings: dict[str, float]) -> Outcome:
        try:
            script = _timed(timings, "parse", lambda: parse_source(command))
        except (LexError, ParseError) as exc:
            reason = Reason(RuleId.R1, None, f"{exc.code}: {exc.message}")
            return self._refuse(command, turn, Decision(Verdict.DENY, (reason,)), frozenset(), timings)

        effects, decision = _timed(timings, "analyze", lambda: self.analyzer.analyze(script, self.state))
        scores = None
        if self.classifier is not None and self.state.denied and decision.verdict is not Verdict.DENY:
            decision, scores = _timed(timings, "classify", lambda: self._classify(command, turn, decision))

        if decision.verdict is Verdict.DENY:
            return self._refuse(command, turn, decision, effects, timings, scores)
        if decision.verdict is Verdict.ESCALATE:
            approved = self.approver is not None and self.approver.approve(command, decision)
            if not approved:
                return self._refuse(command, turn, decision, effects, timings, scores)

        try:
            emitted = _timed(timings, "emit", lambda: emit(script))
        except EmitError as exc:
            decision = decision.tighten(Decision(Verdict.DENY, (Reason(RuleId.R1, None, f"EMIT: {exc}"),)))
            return self._refuse(command, turn, decision, effects, timings, scores)

        result: ExecResult = _timed(
            timings, "execute", lambda: self.executor.run(emitted, self.state, script)
        )
        self.session.record_run(script, effects, result)
        return Outcome(
            turn=turn,
            command=command,
            verdict=Verdict.ALLOW,
            message="",
            decision=decision,
            effects=effects,
            emitted=emitted,
            result=result,
            classifier=scores,
            timings=timings,
        )

    def _classify(
        self, command: str, turn: int, decision: Decision
    ) -> tuple[Decision, dict[str, float] | None]:
        if self.classifier is None:
            return decision, None
        last = self.state.denied[-1]
        try:
            judgement = self.classifier.judge(input_for(last, command, turn))
        except Exception as exc:  # the classifier failing must not cost us its tightening
            detail = f"classifier failed ({type(exc).__name__}), so the retry check could not run"
            return decision.tighten(Decision(Verdict.ESCALATE, (Reason(RuleId.R9, None, detail),))), None
        for spec in judgement.fired:
            if spec.verdict is Verdict.ALLOW:
                continue
            p = judgement.scores.scores[spec.name]
            reason = Reason(RuleId.R9, None, f"{spec.name} p={p:.2f}, compared with turn {last.turn}")
            decision = decision.tighten(Decision(spec.verdict, (reason,)))
        return decision, dict(judgement.scores.scores)

    def _refuse(
        self,
        command: str,
        turn: int,
        decision: Decision,
        effects: frozenset[Effect],
        timings: dict[str, float],
        scores: dict[str, float] | None = None,
    ) -> Outcome:
        self.session.record_refusal(command, decision)
        return Outcome(
            turn=turn,
            command=command,
            verdict=Verdict.DENY,
            message=render(Verdict.DENY, decision, self.level),
            decision=decision,
            effects=effects,
            classifier=scores,
            timings=timings,
        )


def _timed[T](timings: dict[str, float], stage: str, step: Callable[[], T]) -> T:
    start = time.perf_counter()
    try:
        return step()
    finally:
        timings[stage] = time.perf_counter() - start
