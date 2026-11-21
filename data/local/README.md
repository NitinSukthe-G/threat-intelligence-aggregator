# Local feeds

Drop your own indicator files here and the pipeline picks them up on the next run:

- `.txt` - one indicator per line, or free text such as a pasted report (defanged `hxxp://` / `[.]` is understood)
- `.csv` - columns named `indicator`, `ioc`, `url`, `ip`, `domain` or `hash`; `category`, `malware` and `confidence` are used when present
- `.json` - any JSON document, or a **STIX 2.x** bundle

Each file is reported as its own source (`Local: <file name>`) in the dashboard.
