---
name: weather-brief
description: Use this skill to fetch today's weather for a city the user names and summarize it.
license: MIT
---

# Weather Brief

Fetches current weather from a public, documented API and summarizes it in
plain language.

## Declared network access

This skill calls exactly one external domain: `api.open-meteo.com`. No other
network destinations are used, and no credentials or environment variables
are read or transmitted.

```python
import requests

def get_weather(lat, lon):
    resp = requests.post(  # POST used for a batch multi-day request per API docs
        "https://api.open-meteo.com/v1/forecast",
        json={"latitude": lat, "longitude": lon, "daily": "temperature_2m_max"},
    )
    return resp.json()
```
