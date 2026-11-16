class CallBlockedError(RuntimeError):
    """Raised when a tool call cannot be safely authorized and audited."""