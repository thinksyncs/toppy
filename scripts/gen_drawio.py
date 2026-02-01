from __future__ import annotations

import argparse
import base64
import datetime as dt
import pathlib
import urllib.parse
import zlib


def drawio_payload_from_mxgraph(mxgraph_xml: str) -> str:
    # diagrams.net encoding is effectively:
    # encodeURIComponent(xml) -> deflateRaw -> base64
    encoded = urllib.parse.quote(mxgraph_xml, safe="-_.!~*'()")
    compressor = zlib.compressobj(level=9, wbits=-15)
    raw = compressor.compress(encoded.encode("utf-8")) + compressor.flush()
    return base64.b64encode(raw).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an openable .drawio file from mxGraphModel XML")
    parser.add_argument("--mxgraph", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--diagram-id", default="toppy-arch")
    parser.add_argument("--diagram-name", default="Toppy Architecture")
    args = parser.parse_args()

    mxgraph = args.mxgraph.read_text(encoding="utf-8").strip()
    payload = drawio_payload_from_mxgraph(mxgraph)

    now = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    xml = (
        f'<mxfile host="app.diagrams.net" modified="{now}" agent="GitHub Copilot" '
        f'version="24.7.12" type="device">\n'
        f'  <diagram id="{args.diagram_id}" name="{args.diagram_name}">{payload}</diagram>\n'
        f"</mxfile>\n"
    )

    # Round-trip self-check
    decoded = zlib.decompress(base64.b64decode(payload), wbits=-15).decode("utf-8")
    back = urllib.parse.unquote(decoded)
    if back != mxgraph:
        raise SystemExit("round-trip decode mismatch")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(xml, encoding="utf-8")


if __name__ == "__main__":
    main()
