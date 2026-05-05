# Intrusion Detection

A network intrusion and threat detection utility.

## Features

- Detects port scan behavior
- Flags high-frequency packet sources
- Logs suspicious traffic events
- Supports quiet and no-log modes

## Usage

```bash
python main.py --interface eth0 --quiet
```

## Installation

Install the required runtime dependencies:

```bash
pip install scapy psutil
```

Then run:

```bash
python main.py --interface eth0 --quiet
```

## Testing

Run the unit tests with:

```bash
pip install pytest
python -m pytest tests
```

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the `LICENSE` file for details.
