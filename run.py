import sys
from pathlib import Path
 
# Add current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))
 
if __name__ == "__main__":
    # main.py already handles dependency checking/auto-install internally
    # (see _ensure_python_dependencies in main.py) — no need to duplicate it here.
    import main
    main.main()