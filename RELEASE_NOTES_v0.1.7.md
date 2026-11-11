# CF IP Finder v0.1.7 Release Notes

Release date: 2026-11-11

## Startup fix

- Fix Tkinter startup crash caused by mixing pack and grid geometry managers among direct children of the same stage LabelFrame.
- Put the one-click control row and stage grid into separate child containers, with one geometry manager per parent.
- Add a Windows-only Tk startup smoke test that constructs the application UI and processes idle geometry.

## Portable distribution

- Windows EXE remains a PyInstaller --onefile --windowed portable application. Double-click to run; no installer, MSI or setup wizard is involved.
- All v0.1.6 features remain, including one-click selection, optional candidate filters, manual overrides and retry history.
- The legacy VLESS full-file download engine remains unchanged.
