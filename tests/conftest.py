import sys
from pathlib import Path

# Make the modules in src/ importable the same way main.py imports them
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
