#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if (( $# != 3 )); then
  echo 'Usage: updateHrefs.sh VERIFIED_QUARTERLY.zip OFFICIAL_HTTPS_URL RELEASE_LABEL' >&2
  echo 'The old PHP scraper is retired. Review generated metadata before publishing.' >&2
  exit 2
fi
python3 "$repo/scripts/content_metadata.py" "$1" --url "$2" --release "$3" --stage-legacy
