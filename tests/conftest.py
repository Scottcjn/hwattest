import os

# Set before any fixture (including module/session-scoped ones) can call
# attest(): tests must never touch the real ~/.config/hwattest.
_TEST_XDG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".pytest_tmp", "xdg")
os.environ["XDG_CONFIG_HOME"] = os.path.abspath(_TEST_XDG)
