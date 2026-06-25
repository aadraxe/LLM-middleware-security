"""
query.py
Stage 2: retrieve the most relevant chunks for a question.
(Generation and injection-screening come in later stages.)

Usage:
    python -m rag.query "what is prompt injection?"
"""

import sys
from rag.rag_core import get_collection


def retrieve(question: str, n_results: int = 3):
    """Embed the question and return the top-n most similar chunks."""
    collection = get_collection()
    results = collection.query(
        query_texts=[question],
        n_results=n_results,
    )

    # Chroma returns parallel lists wrapped in an outer list (one per query).
    docs = results["documents"][0]
    metadatas = results["metadatas"][0]
    distances = results["distances"][0]

    hits = []
    for doc, meta, dist in zip(docs, metadatas, distances):
        hits.append({
            "text": doc,
            "source": meta.get("source", "unknown"),
            "distance": dist,  # lower = more similar
        })
    return hits


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python -m rag.query "your question here"')
        sys.exit(1)

    question = sys.argv[1]
    print(f"\nQuestion: {question}\n")
    print("Top retrieved chunks:\n")

    for i, hit in enumerate(retrieve(question), 1):
        print(f"[{i}] source={hit['source']}  distance={hit['distance']:.3f}")
        print(f"    {hit['text'][:200]}...")
        print()