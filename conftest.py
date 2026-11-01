import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Keep tests hermetic: app.main calls load_dotenv() on import, which would pull a
# real GROQ_API_KEY (and PIPELINE_MODE etc.) from .env into the test process.
try:
    import dotenv
    dotenv.load_dotenv = lambda *args, **kwargs: False
except ImportError:
    pass
