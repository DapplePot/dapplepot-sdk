"""Run all dapplepot-sdk test suites."""

import sys
import unittest

SUITES = [
    'tests.test_event_capture',
    'tests.test_pii_scrubbing',
    'tests.test_sampling',
    'tests.test_control_channel',
    'tests.test_error_handling',
    'tests.test_graceful_shutdown',
    'tests.test_security_alerts',
]

loader = unittest.TestLoader()
suite = unittest.TestSuite()

for module in SUITES:
    try:
        suite.addTests(loader.loadTestsFromName(module))
    except ModuleNotFoundError as exc:
        print(f'SKIP {module}: {exc}')

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
