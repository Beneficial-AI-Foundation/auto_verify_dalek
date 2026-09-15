from __future__ import annotations

import asyncio
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import model
from tests.test_restart_budget import ENTRIES, _checkpoint_state


class ProviderRecoveryTests(unittest.TestCase):
    def test_cancelled_call_retains_ambiguous_reservation_for_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = _checkpoint_state(Path(temporary))
            entry = ENTRIES["scout-001"]
            state["run_round"] = mock.Mock(side_effect=asyncio.CancelledError)
            accepted = copy.deepcopy(state["accepted"])

            with self.assertRaises(asyncio.CancelledError):
                model._model_request(
                    state,
                    request_id=entry["request"]["request_id"],
                    role=entry["request"]["role"],
                    input_hashes=entry["request"]["input_hashes"],
                    call_kind="framework",
                )

            self.assertEqual(state["receipts"], [])
            pending = state["pending_model_exchanges"]["scout-001"]
            self.assertEqual(pending["request"], entry["request"])
            self.assertEqual(pending["call_kind"], "framework")
            self.assertEqual(pending["dispatch_state"], "ambiguous")
            self.assertEqual(state.get("model_exchanges", {}), {})
            self.assertEqual(state["accepted"], accepted)
            self.assertIn(
                "model:scout-001:reserved:framework", state["run"]["events"]
            )
            self.assertIn("model:scout-001:cancelled", state["run"]["events"])


if __name__ == "__main__":
    unittest.main()
