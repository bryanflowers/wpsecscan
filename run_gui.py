import sys
from wpsecscan.gui import main

if __name__ == "__main__":
    # Round-60: installer registers `--minimized` autostart so the GUI
    # launches into the system tray instead of grabbing focus.
    minimized = "--minimized" in sys.argv or "--minimised" in sys.argv
    main(minimized=minimized) if "minimized" in main.__code__.co_varnames else main()
