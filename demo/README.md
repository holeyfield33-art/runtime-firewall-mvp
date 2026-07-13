# Aletheia Firewall - Demo

Shows the firewall blocking malicious npm packages at `require()` time while
letting a normal package through.

## Run it

```bash
bash demo/demo.sh
```

## What's here

- `modules/evil-miner.js` - cryptojacker (crypto-miner signature)
- `modules/evil-stealer.js` - reads `.env` and exfiltrates it (credential theft)
- `modules/nice-analytics.js` - a NORMAL SDK: reads `process.env` + calls HTTPS
- `run-malware.js` / `run-clean.js` - two tiny apps that load those dependencies

The firewall blocks the two malicious modules and allows the normal one - the
key point being it does not false-alarm on ordinary env + network code.
