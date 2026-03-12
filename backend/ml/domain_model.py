import re


suspicious_keywords = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "auth"
]


def domain_ml_check(domain):

    score = 0

    # long domains suspicious
    if len(domain) > 25:
        score += 20

    # numbers in domain
    if re.search(r'\d', domain):
        score += 15

    # suspicious keywords
    for word in suspicious_keywords:
        if word in domain:
            score += 25

    # too many hyphens
    if domain.count("-") >= 2:
        score += 20

    if score >= 40:
        return "BLOCK", "ml_domain"

    return "ALLOW", "ml_domain"