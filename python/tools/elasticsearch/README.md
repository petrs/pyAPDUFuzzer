# Usage

```
Create a file in /python/tools/elasticsearch/.password containing the password for basic auth
```

```
usage: python import_json.py [-h] --id ID --in IN_FILE [--ignore-existing]
                            [--delete-index]

Import Results

optional arguments:
  -h, --help         show this help message and exit
  --id ID            Card Identifier
  --in IN_FILE       Input file
  --ignore-existing  Overwrite indices
  --delete-index     Deletes indices before insertion
```