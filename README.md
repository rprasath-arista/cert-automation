# Arista EOS Certificate Automation (CVP)

Replaces self-signed certs on Arista EOS switches with CA-signed certs
via CVP configlets. Make-before-break -- connectivity is never
interrupted. Configlets are assigned to devices and tasks are created
for you to execute in CVP.

## Setup

```
pip install -r requirements.txt
```

## Usage

```
python3 cert_automation.py
```

### 1. Manage Switches

View, add (CSV or manual), or delete switches from inventory.

### 2. Generate Keys & CSRs

Creates a private key + CSR per switch. Send `certs/<hostname>/switch.csr`
to your CA provider.

### 3. Import / Generate Certs

- **From directory** -- folder of `<hostname>.crt` files + CA chain
- **Individual files** -- specify each cert path
- **Test certs** -- generates a fake CA and signs test certs (lab only)

### 4. Deploy via CVP Configlet

Connects to CVP (service account token), then:

1. Runs pre-flight checks on each device
2. Auto-skips devices not ready
3. Creates/updates an `SSL_CERT_<hostname>` configlet per device
4. Assigns the configlet to the device (creates a task)
5. Batched with confirm between sections

Go to **CVP > Tasks** to execute the tasks and push config.

### 5. Verify Certs

Connects to each switch over HTTPS and reports self-signed vs CA-signed.

### 6. Rollback

Deletes `SSL_CERT_*` configlets from CVP.

## Pre-flight Checks

Before deploying, the script checks each device in CVP:

- Present in CVP inventory
- Not in the Undefined container
- Approved / provisioned in topology
- No SSL/cert config in designed or reconciled configlets

Devices that fail are auto-skipped with a message on what to fix.

## Workflow

```
1. Add switches (CSV or manual)
2. Generate keys & CSRs
3. Send CSRs to CA provider (or use test certs for lab)
4. Import signed certs + CA chain
5. Deploy via CVP (creates configlets + tasks)
6. Execute tasks in CVP
7. Verify certs on switches
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| CVP connection failed | Check URL and service account token |
| In Undefined container | Move device to a proper container in CVP |
| Not provisioned | Approve the device in CVP topology |
| SSL conflict (skipped) | Remove SSL config from CVP configlet first |
| Key mismatch on import | Cert wasn't signed from the CSR; regenerate |
