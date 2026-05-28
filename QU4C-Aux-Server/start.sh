#!/usr/bin/env bash
SIZE="${1:-384}"
sudo python3 test_quic.py "$SIZE"
