# Forgex Examples

## 1. Triage a directory of extracted evidence

```bash
forgex evidence add ./extracted_evidence --copy --notes "USB dump from workstation-07"
forgex evidence list --json
forgex evidence verify <evidence-id>
```

## 2. Run a Quick investigation and get a Markdown report

```bash
forgex investigate ./extracted_evidence --profile quick --format markdown -o report.md
```

## 3. Ransomware triage (entropy-cluster detection)

```bash
forgex investigate ./extracted_evidence --profile ransomware --format html -o ransomware_report.html
```

## 4. Pull IOCs out of a browser history export or log file

```bash
forgex util ioc ./browser_history_export.txt --json
```

## 5. Inspect a suspicious binary

```bash
forgex util identify ./sample.bin
forgex util entropy ./sample.bin
forgex util strings ./sample.bin --min-length 6
python3 -c "from modules.malware.analyzer import analyze; print(analyze('./sample.bin'))"
```

## 6. Parse browser artifacts directly (Python API)

```python
from modules.browser.artifacts import parse_chrome_history, parse_chrome_downloads

history = parse_chrome_history("/path/to/Default/History")
downloads = parse_chrome_downloads("/path/to/Default/History")
```

## 7. Build a correlation graph and query it

```python
from core.correlation import CorrelationEngine

g = CorrelationEngine()
g.add_node("user:jdoe", "user", "jdoe")
g.add_node("proc:4821", "process", "powershell.exe")
g.add_node("file:payload", "file", "payload.exe")
g.add_edge("user:jdoe", "proc:4821", "EXECUTED")
g.add_edge("proc:4821", "file:payload", "WROTE")

print(g.related("user:jdoe", max_depth=2))
```
