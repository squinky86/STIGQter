#!/usr/bin/env python3
#
# STIGQter - STIG fun with Qt
#
# Copyright © 2018–2026 Jon Hood, http://www.hoodsecurity.com/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Generate src/800-53-rev5-controls.xml from the authoritative NIST OSCAL
SP 800-53 Rev 5 control catalog.

The output mirrors the structure of the legacy Rev 4 SCAP feed
(src/800-53-rev4-controls.xml) so that WorkerCCIAdd's existing
QXmlStreamReader parser can consume it unchanged: a <controls:controls>
root whose children are <controls:control>/<control-enhancement> elements,
each carrying <family>, <number>, <title>, and <description>.

Control numbers use the same textual form the Rev 4 file used and that
DbManager::AddControl / GetControl parse:
    base control     ->  "AC-1"
    enhancement      ->  "AC-2 (1)"

Usage:
    scripts/generate_rev5_controls.py [--source URL_OR_PATH] [--output PATH]

With no arguments it downloads the catalog from NIST's GitHub mirror and
writes src/800-53-rev5-controls.xml relative to the repository root.
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from xml.sax.saxutils import escape

DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUTPUT = os.path.join(REPO_ROOT, "src", "800-53-rev5-controls.xml")

# {{ insert: param, <id> }}
_INSERT_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([^\s}]+)\s*\}\}")
# collapse runs of whitespace introduced when stitching prose fragments
_WS_RE = re.compile(r"\s+")


def load_catalog(source):
    """Load the OSCAL catalog from a URL or a local file path."""
    if source.startswith("http://") or source.startswith("https://"):
        req = urllib.request.Request(source, headers={"User-Agent": "STIGQter"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
    else:
        with open(source, "rb") as fh:
            data = fh.read()
    return json.loads(data)


def prop(node, name):
    """Return the first property value with the given name, or ''."""
    for p in node.get("props", []):
        if p.get("name") == name:
            return p.get("value", "")
    return ""


def is_withdrawn(node):
    return prop(node, "status") == "withdrawn"


def build_param_map(catalog):
    """Map every parameter id in the catalog to human-readable insert text."""
    params = {}

    def register(param):
        pid = param.get("id")
        if not pid:
            return
        if "select" in param:
            sel = param["select"]
            choices = [c if isinstance(c, str) else c.get("prose", "")
                       for c in sel.get("choice", [])]
            how = sel.get("how-many", "one")
            params[pid] = "[Selection (%s): %s]" % (how, "; ".join(choices))
        elif param.get("label"):
            params[pid] = "[Assignment: %s]" % param["label"]
        elif param.get("guidelines"):
            prose = " ".join(g.get("prose", "") for g in param["guidelines"])
            params[pid] = "[Assignment: %s]" % prose.strip().rstrip(";")
        else:
            params[pid] = "[Assignment: organization-defined parameter]"

    def walk(node):
        for param in node.get("params", []):
            register(param)
        for child in node.get("controls", []):
            walk(child)

    for group in catalog.get("groups", []):
        for param in group.get("params", []):
            register(param)
        for control in group.get("controls", []):
            walk(control)
    return params


def resolve_params(text, param_map):
    # A resolved value (e.g. a "select" param) may itself embed further insert
    # markers via its choices, so substitute repeatedly until the text is stable.
    for _ in range(10):
        new_text = _INSERT_RE.sub(
            lambda m: param_map.get(m.group(1), "[Assignment: organization-defined parameter]"),
            text,
        )
        if new_text == text:
            return new_text
        text = new_text
    return text


def label_of(part):
    return prop(part, "label")


def assemble_statement(part, param_map):
    """Recursively flatten a 'statement'/'item' part tree into one string."""
    pieces = []
    label = label_of(part)
    prose = resolve_params(part.get("prose", ""), param_map)
    head = ((label + " ") if label else "") + prose
    head = head.strip()
    if head:
        pieces.append(head)
    for sub in part.get("parts", []):
        if sub.get("name") in ("statement", "item"):
            child = assemble_statement(sub, param_map)
            if child:
                pieces.append(child)
    return " ".join(pieces)


def description_for(control, param_map):
    """Build the control description from its 'statement' part."""
    for part in control.get("parts", []):
        if part.get("name") == "statement":
            text = assemble_statement(part, param_map)
            if text:
                return _WS_RE.sub(" ", text).strip()
    if is_withdrawn(control):
        return "[Withdrawn]"
    # Fall back to guidance prose when a control has no formal statement.
    for part in control.get("parts", []):
        if part.get("name") == "guidance":
            text = resolve_params(part.get("prose", ""), param_map)
            if text:
                return _WS_RE.sub(" ", text).strip()
    return ""


def format_number(control_id):
    """oscal id -> Rev 4 style control number. 'ac-1'->'AC-1', 'ac-2.1'->'AC-2 (1)'."""
    family, _, remainder = control_id.partition("-")
    family = family.upper()
    if "." in remainder:
        base, enh = remainder.split(".", 1)
        return "%s-%s (%s)" % (family, base, enh)
    return "%s-%s" % (family, remainder)


def emit_control(out, control, family_name, param_map, tag):
    number = format_number(control["id"])
    title = control.get("title", "").upper()
    description = description_for(control, param_map)
    out.append("    <controls:%s>" % tag if tag == "control" else "    <%s>" % tag)
    out.append("        <family>%s</family>" % escape(family_name))
    out.append("        <number>%s</number>" % escape(number))
    out.append("        <title>%s</title>" % escape(title))
    out.append("        <description>%s</description>" % escape(description))
    out.append("    </controls:%s>" % tag if tag == "control" else "    </%s>" % tag)


def generate(catalog):
    meta = catalog.get("metadata", {})
    pub_date = meta.get("last-modified", meta.get("published", ""))
    version = meta.get("version", "")

    out = []
    out.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    out.append('<controls:controls xmlns="http://scap.nist.gov/schema/sp800-53/2.0"')
    out.append('    xmlns:controls="http://scap.nist.gov/schema/sp800-53/feed/2.0"')
    out.append('    xmlns:xhtml="http://www.w3.org/1999/xhtml" '
               'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')
    out.append('    pub_date="%s" revision="5" catalog_version="%s">'
               % (escape(pub_date), escape(version)))

    n_controls = 0
    n_enh = 0
    for group in catalog.get("groups", []):
        # OSCAL groups are the 800-53 families; class="family".
        family_name = group.get("title", "").upper()
        for control in group.get("controls", []):
            emit_control(out, control, family_name, param_map=PARAM_MAP, tag="control")
            n_controls += 1
            for enh in control.get("controls", []):
                emit_control(out, enh, family_name, param_map=PARAM_MAP,
                             tag="control-enhancement")
                n_enh += 1

    out.append("</controls:controls>")
    out.append("")
    return "\n".join(out), n_controls, n_enh


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", default=DEFAULT_SOURCE,
                        help="OSCAL Rev 5 catalog URL or local JSON path")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="destination XML path")
    args = parser.parse_args()

    sys.stderr.write("Loading OSCAL catalog from %s\n" % args.source)
    catalog = load_catalog(args.source)["catalog"]

    global PARAM_MAP
    PARAM_MAP = build_param_map(catalog)

    xml, n_controls, n_enh = generate(catalog)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(xml)

    sys.stderr.write(
        "Wrote %s\n  base controls: %d\n  enhancements:  %d\n  total:         %d\n"
        % (args.output, n_controls, n_enh, n_controls + n_enh)
    )


if __name__ == "__main__":
    main()
