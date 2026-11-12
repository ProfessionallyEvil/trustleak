"""
TrustLeak — internal path resolution helper.

Locates a schema JSON file regardless of which of the two layouts this
package was laid out in:
  - flat:   .../trustleak/schema.py, .../trustleak/schemas/*.json
            (the "trustleak" folder IS the package, schemas/ sits inside it)
  - nested: .../trustleak_prep/trustleak/schema.py,
            .../trustleak_prep/schemas/*.json
            (schemas/ is a sibling of the "trustleak" package folder)

Both are real layouts this project has shipped with depending on how it
was unzipped/cloned — see schema.py and importer.py, the two callers.
"""
import os


def find_schema(filename):
    """
    Return the absolute path to `filename` inside a 'schemas/' directory,
    checking both alongside this file and one level up. Raises
    FileNotFoundError with a clear message if neither location has it,
    rather than a bare "file not found" pointing at the wrong guess.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "schemas", filename),
        os.path.join(here, "..", "schemas", filename),
    ):
        if os.path.isfile(candidate):
            return candidate

    raise FileNotFoundError(
        f"Could not locate '{filename}'. Expected a 'schemas/' directory "
        f"either inside {here} or as its sibling — checked both and found neither."
    )
