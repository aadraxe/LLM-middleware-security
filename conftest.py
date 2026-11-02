import sys, os
from pathlib import Path

# Keep tempfile probes and pytest artifacts inside the ignored workspace path.
_test_tmp = Path(__file__).resolve().parent / ".test-tmp"
_test_tmp.mkdir(exist_ok=True)
os.environ["TMPDIR"] = str(_test_tmp)
import tempfile
tempfile.tempdir = str(_test_tmp)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Keep tests hermetic: app.main calls load_dotenv() on import, which would pull a
# real GROQ_API_KEY (and PIPELINE_MODE etc.) from .env into the test process.
try:
    import dotenv
    dotenv.load_dotenv = lambda *args, **kwargs: False
except ImportError:
    pass
