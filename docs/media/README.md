# Walkthrough media

Generated — do not edit by hand. These files are rendered from the animated walkthrough
project and refreshed with its `export/sync-to-mwe.sh`.

| file | what it is |
|---|---|
| `00-full-walkthrough.webm` | every scenario in one continuous film, with chapter cards |
| `00-full-walkthrough.chapters.txt` | chapter marks for the film |
| `0N-<scenario>.gif` | one scenario, loopable, for inline display in a README |

Per-scenario WebM files are not kept here: they duplicate the GIFs at a similar size, and a
repository pays for every committed byte on every clone. Run
`export/capture.mjs --format=video` in the walkthrough project to produce them.

The walkthrough shows mechanism and method only. It carries no measurement results, so it
can be read as an explanation of how the attack and the harness work without being mistaken
for the evaluation.
