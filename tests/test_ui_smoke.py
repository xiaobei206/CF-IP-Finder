import os
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

import cf_ip_finder as app


@unittest.skipUnless(os.name == "nt", "Tk UI smoke test runs on the Windows CI worker")
class TkStartupSmokeTests(unittest.TestCase):
    def test_main_window_constructs_without_geometry_manager_error(self):
        root = tk.Tk()
        root.withdraw()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with patch.object(app, "APP_DIR", Path(temp_dir)):
                    window = app.App(root)
                    root.update_idletasks()
                    self.assertTrue(window.auto_btn.winfo_exists())
                    self.assertTrue(window.stage_buttons)
        finally:
            try:
                root.destroy()
            except tk.TclError:
                pass


if __name__ == "__main__":
    unittest.main()
