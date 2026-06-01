import requests
import tldextract
import re

from pathlib import Path

RAW_OUTPUT = "output/rkn_raw.txt"
FINAL_OUTPUT = "output/russia-blocked.txt"

BLOCKEDIN_DOMAINS = "https://blockedin.org/api/v3/domains/"
BLOCKEDIN_IPS = "https://blockedin.org/api/v3/ips/"


def fetch_json(url):
    r = requests.get(
        url,
        timeout=120
    )

    r.raise_for_status()

    body = r.text.strip()

    if not body:
        return []

    return r.json()


def normalize_domain(domain):

    domain = str(domain).strip().lower()

    domain = domain.replace('"', '')

    domain = re.sub(
        r"^https?://",
        "",
        domain
    )

    domain = domain.split("/")[0]

    ext = tldextract.extract(domain)

    if not ext.domain:
        return None

    return ".".join(
        x
        for x in [ext.domain, ext.suffix]
        if x
    )


def collect_domains():

    result = set()

    data = fetch_json(
        BLOCKEDIN_DOMAINS
    )

    if isinstance(data, list):

        for item in data:

            domain = normalize_domain(item)

            if domain:
                result.add(domain)

    return result


def collect_ips():

    result = set()

    try:

        data = fetch_json(
            BLOCKEDIN_IPS
        )

        if isinstance(data, list):

            for item in data:
                result.add(
                    str(item).strip()
                )

    except Exception as e:

        print(
            "IPS ERROR:",
            e
        )

    return result


def load_patterns():

    try:

        with open(
            "filters/exclude_patterns.txt",
            encoding="utf-8"
        ) as f:

            return [
                x.strip().lower()
                for x in f
                if x.strip()
            ]

    except:

        return []


def load_cities():

    try:

        with open(
            "filters/cities.txt",
            encoding="utf-8"
        ) as f:

            return [
                x.strip().lower()
                for x in f
                if x.strip()
            ]

    except:

        return []


def load_manual():

    try:

        with open(
            "sources/manual_geoblocked.txt",
            encoding="utf-8"
        ) as f:

            return {
                x.strip().lower()
                for x in f
                if x.strip()
            }

    except:

        return set()


def should_skip_by_pattern(
    domain,
    patterns
):

    d = domain.lower()

    for pattern in patterns:

        if pattern in d:
            return True

    return False


def contains_city(
    domain,
    cities
):

    d = domain.lower()

    for city in cities:

        if city in d:
            return True

    return False


def looks_like_mirror(domain):

    name = domain.split(".")[0]

    digits = sum(
        c.isdigit()
        for c in name
    )

    if digits >= 4:
        return True

    if re.search(
        r"\d+-\d+",
        name
    ):
        return True

    return False


def save_file(
    path,
    entries
):

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        for item in sorted(entries):
            f.write(item + "\n")


def main():

    Path(
        "output"
    ).mkdir(
        exist_ok=True
    )

    domains = collect_domains()

    ips = collect_ips()

    save_file(
        RAW_OUTPUT,
        domains | ips
    )

    print(
        f"RAW: {len(domains)} domains"
    )

    patterns = load_patterns()

    cities = load_cities()

    filtered = set()

    for domain in domains:

        if should_skip_by_pattern(
            domain,
            patterns
        ):
            continue

        if contains_city(
            domain,
            cities
        ):
            continue

        if looks_like_mirror(
            domain
        ):
            continue

        filtered.add(
            domain
        )

    filtered |= load_manual()

    final = filtered | ips

    save_file(
        FINAL_OUTPUT,
        final
    )

    print(
        f"FINAL: {len(final)} entries"
    )


if __name__ == "__main__":
    main()
