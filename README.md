# 🦉 OTreeMap

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Core%20/%20Utilities-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OTreeMap** — Disk Usage Treemap Analyzer ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OTreeMap is a professional, offline-first Disk Usage Treemap Analyzer with an interactive red/black TUI and a full CLI (flag-based) supporting txt|md|json|csv|sarif exports, MITRE ATT&CK tagging on findings where meaningful, and A+..F posture grading.

---

## ✨ Features

- Analyze disk usage with treemap-oriented views
- Top directories/files, extension stats and age/perms insights
- Hot-spot detection, compression estimates and recommendations
- Snapshot/baseline compare for growth tracking
- Configurable depth, size filters and symlink policy
- Export usage reports in multiple formats

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OTreeMap OTreeMap.go
./OTreeMap --help
./OTreeMap --path /var --max-depth 3 --treemap
./OTreeMap --path /home --ext-stats --top 20
./OTreeMap --path /data --snapshot snap.json --baseline old.json
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad
