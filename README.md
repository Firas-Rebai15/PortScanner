# Port Scanner

A small Python TCP connect scanner for hosts you own or are explicitly authorized to test.

## Usage

```powershell
python .\port_scanner.py localhost -p 22,80,443
python .\port_scanner.py 127.0.0.1 -p 1-1024 -t 0.25 -w 64
```

The scanner uses ordinary TCP connections, reports open ports, and performs no service
exploitation or raw-packet scanning. Keep scans within systems and networks where you have
permission.

## Next steps

- Add unit tests and structured output (JSON/CSV).
- Add optional banner detection with a strict timeout.
- Add rate limiting and an allowlist for safer repeated scans.

## GitHub workflow

After creating an empty GitHub repository named `PortScanner`, connect it and publish:

```powershell
git add .
git commit -m "Initial port scanner"
git remote add origin https://github.com/YOUR-USERNAME/PortScanner.git
git push -u origin main
```

For later changes:

```powershell
git add .
git commit -m "Describe the change"
git push
```
