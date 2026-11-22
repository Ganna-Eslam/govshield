from detect import detect, normalize


def validate(safe_text, mapping):
    norm_safe = normalize(safe_text)
    for original in mapping.values():
        if normalize(original) in norm_safe:
            return False, "original value still present"
    if detect(safe_text):
        return False, "sensitive pattern still present"
    return True, "ok"