# Results corpus

`make compare` regenerates `FACTS.md` from valid `report.jsonl` under `results/<arm>/<scan-id>/`. Trees under `INVALID/` are skipped.

HTTP_CODE 24/24 vs 0/24 vs 0/24 lives in [docs/12-what-we-measured.md](../docs/12-what-we-measured.md). That table is a reachability cell. It is a different computation from taxonomy `hit` unions in `FACTS.md`.

Directory names under `results/<arm>/` are scan ids the harness writes (UTC timestamps). Cite the HTTP_CODE table in docs/12. Cite taxonomy buckets from the `FACTS.md` `make compare` just wrote.
