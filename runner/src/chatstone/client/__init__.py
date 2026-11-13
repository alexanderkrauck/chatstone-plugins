"""Python REST client. No database or service dependency is imported."""
from .transport import Client, ClientError

__all__ = ['Client', 'ClientError']
