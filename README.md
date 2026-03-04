# role-aggregator

Aggregate `ClusterRole` and `Role` rules from a directory of YAMLs into a single `ClusterRole`.

## Usage

```bash
go run *.go \
  --dir /path/to/clusterroles \
  --chart /path/to/chart-a \
  --chart /path/to/chart-b \
  --name combined-roles \
  --output /path/to/combined.yaml
```

If `--output` is not set, the aggregated YAML is written to stdout.

## Notes

- Only `ClusterRole` and `Role` objects are processed; other kinds are ignored.
- Each `--chart` directory is rendered with `helm template` before processing.
- Rules are aggregated by apiGroup, resource, and resourceNames. Non-resource URLs are aggregated separately.
- Multiple YAML documents in a single file are supported.
