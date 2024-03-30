import codecs
import json
import random
import re
import string
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Union


def is_ipv4(text: str) -> bool:
    try:
        return type(ip_address(text)) is IPv4Address
    except Exception:
        return False


def is_ipv6(text: str) -> bool:
    try:
        return type(ip_address(text)) is IPv6Address
    except Exception:
        return False


def load_json_data(json_filename: str):
    return json.load(codecs.open(json_filename, "r", "utf-8-sig"))


def anonymise_dict(json_data: dict) -> dict:
    def anonymise_fields(value: Any) -> Union[str, int, float, Any]:
        if isinstance(value, str):
            if is_ipv4(value):
                return "00.00.00.00"

            elif is_ipv6(value):
                return "0:0:0:0:0:0:0:0"

            return "".join(
                random.choice(string.ascii_letters) for _ in range(len(value))
            )

        elif isinstance(value, int):
            return random.randint(0, 1000)

        elif isinstance(value, float):
            return round(random.uniform(0, 1000), 2)

        elif isinstance(value, list):
            return [anonymise_fields(item) for item in value]

        elif isinstance(value, dict):
            return {item: anonymise_fields(v) for item, v in value.items()}

        return value

    return anonymise_fields(json_data)


if __name__ == "__main__":
    import os

    directory = "/workspaces/aperture-test/scripts/tenable"

    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        data = load_json_data(f)
        anonymise_data = anonymise_dict(data)

        with open(
            os.path.join(
                "/workspaces/aperture-test/transforms/tests/data/tenable", filename
            ),
            "w",
        ) as f:
            json.dump(anonymise_data, f)

    s
