import json
import datetime


def load_domain_list(file_path):

    with open(file_path, "r") as file:
        domains = [line.strip() for line in file]

    return set(domains)


trusted_domains = load_domain_list("reputation/trusted_domains.txt")
malicious_domains = load_domain_list("reputation/malicious_domains.txt")
blacklist_domains = load_domain_list("reputation/blacklist.txt")


def load_rules():

    try:
        with open("rules/rules.json", "r") as file:
            return json.load(file)
    except:
        return []


def check_time(rule):

    now = datetime.datetime.now().time()

    start = datetime.datetime.strptime(rule["start"], "%H:%M").time()
    end = datetime.datetime.strptime(rule["end"], "%H:%M").time()

    return start <= now <= end


def check_domain_reputation(domain):

    # malicious domains always blocked
    if domain in blacklist_domains:
        return "BLOCK", "manual"

    # trusted domains always allowed
    if domain in trusted_domains:
        return "ALLOW", "trusted"

    # manual block
    if domain in malicious_domains:
        return "BLOCK", "malicious"

    # rule engine
    rules = load_rules()

    for rule in rules:

        if rule["domain"] == domain:

            if rule["mode"] == "permanent":
                return "BLOCK", "manual"

            if rule["mode"] == "time":

                if check_time(rule):
                    return "BLOCK", "manual"

    return "ALLOW", "unknown"