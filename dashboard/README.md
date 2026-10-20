# Dashboard – Setup

## Files
- `requirements.txt` (repo root): Flask 3.1.3 and pytest 9.1.1, pinned.
- `pytest.ini` (repo root): tells pytest to look in `dashboard/tests`.
- `.gitignore` (repo root): ignores `.venv/`, `__pycache__/`, `.pytest_cache/`.

## Commands (Windows, run from repo root `Packet_sniffer/`)
| Step | Command | Output |
|---|---|---|
| Create virtual environment | `python -m venv .venv` | `.venv/` folder |
| Activate it | `.venv\Scripts\activate` | `(.venv)` appears in the prompt |
| Install packages | `pip install -r requirements.txt` | Flask and pytest installed |
| Run tests | `pytest -v` | `2 passed` |

# PPS-5 – Dashboard Skeleton

## Functions (`app.py`)

### `load_mock_data()`
- **Input arguments:** none
- **Output:** a Python dictionary read from `mock/mock_data.json`

### `index()`  → route `GET /`
- **Input arguments:** none
- **Output:** the HTML page `templates/index.html` with four empty labelled panels: Session Controls, Live Traffic Statistics, Hosts, Alerts

### `mock()`  → route `GET /api/mock`
- **Input arguments:** none
- **Output:** the mock data as JSON, with keys `packets_per_sec`, `top_talkers`, `protocols`, `hosts`, `alerts`