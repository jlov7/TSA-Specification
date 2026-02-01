from tests import run_tests


def test_run_tests_harness():
    _, failed = run_tests.run_all(verbose=False)
    assert failed == 0
