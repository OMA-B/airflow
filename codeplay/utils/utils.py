import json
import os
from collections import defaultdict
from xml.etree import cElementTree as ET


def get_supported_file_type(file_path: str) -> str:
    filename = os.path.basename(file_path)

    if filename is None or filename == "":
        raise ValueError("Empty Filename given")

    file_extension = filename.split(".")[-1].lower()

    supported_file_types = {"json": "JSON", "xml": "XML", "csv": "CSV"}

    if file_extension not in supported_file_types:
        raise ValueError(
            f"Not a supported file type '{file_extension}' supported are '{supported_file_types}'"
        )

    return supported_file_types[file_extension]


def open_json_file(file_path: str) -> dict:
    with open(file_path, "r", encoding="utf-8-sig") as file:
        return json.load(file)


def etree_to_dict(t):
    d = {t.tag: {} if t.attrib else None}
    children = list(t)
    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.items():
                dd[k].append(v)
        d = {t.tag: {k: v[0] if len(v) == 1 else v for k, v in dd.items()}}
    if t.attrib:
        d[t.tag].update(("@" + k, v) for k, v in t.attrib.items())
    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
                d[t.tag]["#text"] = text
        else:
            d[t.tag] = text
    return d


def open_xml_file(file_path: str) -> dict:
    root = ET.parse(file_path).getroot()
    data = etree_to_dict(root)

    return data


if __name__ == "__main__":
    from pprint import pprint

    fp = "/workspaces/aperture-transform/transforms/transforms/tests/data/qualys/qualys_detections.xml"
    pprint(open_xml_file(fp))
