import requests
import tldextract
import re
from pathlib import Path

OUTPUT = "output/russia-blocked.txt"

BLOCKEDIN_DOMAINS = "https://blockedin.org/api/v3/domains/"
BLOCKEDIN_DPI = "https://blockedin.org/api/v3/dpi/"
BLOCKEDIN_IPS = "https://blockedin.org/api/v3/ips/"


def load_keywords():
    with open(
        "filters/exclude_keywords.txt",
        encoding="utf-8"
    ) as f:
        return {
            x.strip().lower()
            for x in f
            if x.strip()
        }


def normalize_domain(domain):
    domain = domain.lower().strip()

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
        part for part in [
            ext.domain,
            ext.suffix
        ]
        if part
    )


def contains_bad_keyword(text, keywords):
    text = text.lower()

    for kw in keywords:
        if kw in text:
            return True

    return False


def fetch_json(url):
    r = requests.get(
        url,
        timeout=60
    )

    r.raise_for_status()

print(r.url)
print(r.status_code)
print(r.headers.get("content-type"))
print(r.text[:1000])
    
    return r.json()


def collect_domains():
    result = set()

    data = fetch_json(
        BLOCKEDIN_DOMAINS
    )

    if isinstance(data, list):
        for item in data:
            domain = normalize_domain(
                str(item)
            )

            if domain:
                result.add(domain)

    return result


def collect_dpi():
    result = set()

    data = fetch_json(
        BLOCKEDIN_DPI
    )

    if isinstance(data, list):
        for item in data:
            domain = normalize_domain(
                str(item)
            )

            if domain:
                result.add(domain)

    return result


def collect_ips():
    result = set()

    data = fetch_json(
        BLOCKEDIN_IPS
    )

    if isinstance(data, list):
        for item in data:
            result.add(str(item).strip())

    return result


def main():
    keywords = load_keywords()

    domains = set()

    domains |= collect_domains()
    domains |= collect_dpi()

    domains = {
        d for d in domains
        if not contains_bad_keyword(
            d,
            keywords
        )
    }

    ips = collect_ips()

    final = sorted(
        domains | ips
    )

    Path(
        "output"
    ).mkdir(
        exist_ok=True
    )

    with open(
        OUTPUT,
        "w",
        encoding="utf-8"
    ) as f:
        for item in final:
            f.write(item + "\n")

    print(
        f"saved {len(final)} entries"
    )


if __name__ == "__main__":
    main()
