import secrets


def mask(text, detections):
    """بترجع (safe_text, mapping) والـmapping هو token -> original، ومحلي بس."""
    mapping = {}
    value_to_token = {}
    out = text

    for d in sorted(detections, key=lambda d: d.start, reverse=True):
        if d.value not in value_to_token:
            while True:
                token = f"[[{d.type}_{secrets.token_hex(2).upper()}]]"
                if token not in mapping:
                    break
            value_to_token[d.value] = token
            mapping[token] = d.value
        out = out[:d.start] + value_to_token[d.value] + out[d.end:]

    return out, mapping


def restore(text, mapping):
    for token, original in mapping.items():
        text = text.replace(token, original)
    return text