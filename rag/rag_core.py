"""
rag_core.py
Core RAG functions: chunking, and the ChromaDB collection with a
sentence-transformers embedding function (all-MiniLM-L6-v2, runs local on CPU).
"""

import os
import chromadb
from chromadb.utils import embedding_functions

# Where Chroma persists its data on disk
CHROMA_PATH = os.path.join(os.path.dirname(__file__), "chroma_db")

# all-MiniLM-L6-v2: small, fast, CPU-friendly embedding model.
# ChromaDB downloads it automatically the first time (~80MB).
_embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)


def get_collection():
    """Return (creating if needed) the persistent document collection."""
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    return client.get_or_create_collection(
        name="documents",
        embedding_function=_embed_fn,
    )


def chunk_text(text: str, size: int = 200, overlap: int = 30) -> list[str]:
    """
    Split text into overlapping word-based chunks.
    size = words per chunk, overlap = words shared between consecutive chunks
    (overlap keeps context from being cut mid-thought at chunk boundaries).
    """
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunks.append(" ".join(words[i : i + size]))
        i += size - overlap
    return chunks