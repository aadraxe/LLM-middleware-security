"""
ingest.py
Load every .txt file in rag/documents/ into ChromaDB:
read → chunk → embed → store.

Usage:
    python rag/ingest.py
"""

import os
from rag.rag_core import get_collection, chunk_text

DOCS_DIR = os.path.join(os.path.dirname(__file__), "documents")


def ingest():
    collection = get_collection()
    txt_files = [f for f in os.listdir(DOCS_DIR) if f.endswith(".txt")]

    if not txt_files:
        print(f"No .txt files found in {DOCS_DIR}. Drop some documents there first.")
        return

    total_chunks = 0
    for fname in txt_files:
        path = os.path.join(DOCS_DIR, fname)
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()

        chunks = chunk_text(text)
        if not chunks:
            continue

        # Each chunk needs a unique ID and carries its source filename as metadata
        ids = [f"{fname}::chunk_{i}" for i in range(len(chunks))]
        metadatas = [{"source": fname, "chunk_index": i} for i in range(len(chunks))]

        collection.add(documents=chunks, ids=ids, metadatas=metadatas)
        total_chunks += len(chunks)
        print(f"  Ingested {fname}: {len(chunks)} chunks")

    print(f"\nDone. {total_chunks} chunks from {len(txt_files)} file(s) now in ChromaDB.")
    print(f"Total documents in collection: {collection.count()}")


if __name__ == "__main__":
    ingest()