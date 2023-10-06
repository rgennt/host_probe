#!/bin/bash
./venv/bin/python -m json.tool ${1:-"subscriptions.json"} >/dev/null && echo JSON file \"${1:-"subscriptions.json"}\" is valid