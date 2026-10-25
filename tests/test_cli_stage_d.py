import unittest
from unittest.mock import patch

from app.cli.dymasa.cli import main


class CliStageDTests(unittest.TestCase):
    def test_dynamic_start_calls_shared_service(self):
        with patch("app.cli.dymasa.cli._with_session", return_value={"status": "accepted", "job_id": "job-1"}) as session:
            self.assertEqual(main(["--quiet", "dynamic", "start", "job-1"]), 0)
            session.assert_called_once()

    def test_dynamic_start_command_is_available_without_route_http_call(self):
        with patch("app.cli.dymasa.cli._with_session", side_effect=ValueError("A DY-MASA analysis is already running for this job.")):
            self.assertEqual(main(["--quiet", "dynamic", "start", "job-1"]), 1)


if __name__ == "__main__":
    unittest.main()
