# Small, non-destructive training payload set.

ERROR_PAYLOADS = [
    "'",
    '"',
    "''",
]

BOOLEAN_CASES = [
    ("' OR '1'='1", "' OR '1'='2"),
    ('" OR "1"="1', '" OR "1"="2'),
]
