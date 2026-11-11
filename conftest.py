"""Empty on purpose.

Its presence at the repository root puts the root on `sys.path` when pytest runs, so tests can
import the packages under test as `from compiler.types import Verdict` rather than by relative path.
"""
