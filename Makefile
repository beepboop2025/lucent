VENV := .venv
PY := $(VENV)/bin/python
ERC := $(VENV)/bin/erc7730

# Target descriptor (override on the command line, e.g. `make lint DESC=...`)
DESC ?= registry/ens/calldata-ETHRegistrarController.json

.PHONY: setup discover fetch lint preview resolve submission all clean

## discover: classify seed candidates into leads / proxy / covered
discover:
	$(PY) scripts/discover.py $(SEEDS)
## setup: create venv and install tooling
setup:
	python3.12 -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q erc7730 eth-account

## fetch: pull a verified ABI from Sourcify.  make fetch CHAIN=1 ADDR=0x...
fetch:
	$(PY) scripts/fetch_abi.py $(CHAIN) $(ADDR)

## resolve-proxy: cache a proxy's implementation ABI.  make resolve-proxy CHAIN=1 ADDR=0x...
resolve-proxy:
	$(PY) scripts/resolve_proxy.py $(CHAIN) $(ADDR)

## lint: validate a descriptor (add ETHERSCAN key for full ABI comparison)
lint:
	$(ERC) lint --skip-abi-validation $(DESC)

## audit: security/quality grade beyond lint (the verification moat)
audit:
	$(PY) scripts/audit.py $(DESC)

## semverify: prove the screen matches actual on-chain movements (needs ETHERSCAN key)
semverify:
	$(PY) scripts/semverify.py $(DESC)

## resolve: expand a descriptor to resolved form (proves all paths resolve)
resolve:
	COLUMNS=100000 $(ERC) resolve $(DESC) >/dev/null && echo "resolved OK: $(DESC)"

## preview: render on-device screens + emit registry test vectors
preview:
	$(PY) scripts/preview.py

## submission: emit registry-PR form under dist/  (make submission ENTITY=ens)
submission:
	$(PY) scripts/to_submission.py $(ENTITY) $(DESC)

## all: lint + audit + resolve + preview
all: lint audit resolve preview

## clean: remove local scratch artifacts
clean:
	rm -f registry/**/_draft.json registry/**/_resolved.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
