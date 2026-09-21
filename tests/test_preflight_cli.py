import unittest

from autofv import experiment


class PreflightCliTests(unittest.TestCase):
    def test_parser_accepts_exact_preflight_command(self) -> None:
        args = experiment._parser().parse_args(
            [
                "preflight",
                "/tmp/repo",
                "--config",
                "/tmp/run.json",
                "--output",
                "/tmp/evidence",
                "--env-file",
                "/tmp/provider.env",
            ]
        )

        self.assertEqual(args.command, "preflight")
        self.assertEqual(args.repo, "/tmp/repo")
        self.assertEqual(args.config, "/tmp/run.json")
        self.assertEqual(args.output, "/tmp/evidence")
        self.assertEqual(args.env_file, "/tmp/provider.env")


if __name__ == "__main__":
    unittest.main()
