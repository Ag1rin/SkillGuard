---
name: csv-summarizer
description: Use this skill when the user wants a quick statistical summary of a CSV file (row/column counts, column types, basic stats). Trigger on mentions of .csv files or requests to "summarize this spreadsheet".
license: MIT
---

# CSV Summarizer

## Overview
Reads a local CSV file and prints column names, types, and basic statistics
(min/max/mean for numeric columns, unique value counts for categorical ones).

## Usage
```python
import csv

def summarize(path):
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    print(f"{len(rows)} rows, {len(reader.fieldnames)} columns")
    return rows
```

All processing happens locally on the file the user provides. No network
access, no environment variables, no files outside the given path are touched.
