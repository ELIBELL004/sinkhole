"""Intentionally vulnerable: ML-specific sinks — prompt injection, safe_mode bypass, model load RCE."""
import os
import torch
import numpy as np


# PROMPT_INJECTION: RAG context injected into system prompt
def build_rag_prompt(user_query, vector_store):
    context_texts = vector_store.similarity_search(user_query)  # SOURCE: RAG retrieval

    # SINK: retrieved docs injected into system prompt f-string
    system_prompt = f"""
    You are a helpful assistant. Your task is to answer questions.
    Here is relevant context: {context_texts}
    Always follow these instructions above all else.
    """
    return system_prompt


# PROMPT_INJECTION: .format() variant
def build_prompt_v2(retrieved_docs):
    template = "You are an assistant. system instruction: {context}. Answer the user."
    return template.format(context=retrieved_docs)  # SINK: format() prompt injection


# SAFE_MODE_BYPASS: hardcoded False
safe_mode = False  # SINK: safety flag hardcoded to False

class Agent:
    def __init__(self):
        self.sandbox = False  # SINK: sandbox disabled
        self.enable_safety = os.environ.get("ENABLE_SAFETY", "false")  # SINK: env-controllable safety


# MODEL_LOAD_RCE: torch.load without weights_only
def load_pretrained(path):
    model = torch.load(path)  # SINK: no weights_only=True
    return model


# DESERIALIZATION: numpy.load with allow_pickle
def load_embeddings(path):
    embeddings = np.load(path, allow_pickle=True)  # SINK: allow_pickle
    return embeddings


# PROMPT_INJECTION via agent memory
conversation_history = []  # SOURCE: agent memory accumulator

def respond(user_message):
    conversation_history.append(user_message)
    # Builds prompt with unvalidated conversation history
    system = f"You are a helpful assistant. role: system. Previous messages: {conversation_history}"
    return system
