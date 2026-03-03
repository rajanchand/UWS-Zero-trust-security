"""Supabase client singleton."""

from supabase import create_client, Client
from app.config import settings

_client: Client | None = None


def get_supabase() -> Client:
    """Return the shared Supabase client, using service-role key when available."""
    global _client
    if _client is None:
        key = settings.SUPABASE_SERVICE_KEY or settings.SUPABASE_KEY
        _client = create_client(settings.SUPABASE_URL, key)
    return _client
