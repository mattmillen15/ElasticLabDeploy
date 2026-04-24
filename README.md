# ElasticLabDeploy

ElasticLabDeploy is a single-script lab bootstrap tool for standing up Elasticsearch, Kibana, Fleet, Fleet Server, and a hardened Elastic Defend policy with minimal setup.

This project is for isolated lab use only.

## What It Does

- Deploys or repairs the Elastic lab stack
- Applies the hardened Elastic Defend policy by default
- Generates and serves host enrollment files
- Prints health and policy status
- Rebuilds or destroys lab state when needed

## Quick Start

```bash
git clone https://github.com/mattmillen15/ElasticLabDeploy
cd ElasticLabDeploy
sudo ./ElasticLabDeploy.sh
```

Choose `Fresh install / repair lab` on first run.

If the host has multiple NICs, set the public URLs explicitly:

```bash
FLEET_PUBLIC_URL=http://<LAB-IP>:8220 ELASTIC_PUBLIC_URL=http://<LAB-IP>:9200 sudo ./ElasticLabDeploy.sh
```

## Web Access

After install:

- Kibana: `http://<LAB-IP>:5601`
- Elasticsearch: `http://<LAB-IP>:9200`
- Fleet Server: `http://<LAB-IP>:8220`
- Username: `elastic`
- Password: `P@ssw0rd`

## Main Menu

- `Fresh install / repair lab`
  Deploys or repairs Elasticsearch, Kibana, Fleet, Fleet Server, and the hardened Elastic Defend setup.

- `Enroll a host`
  Prompts for OS/architecture, temporarily hosts the enrollment files over HTTP, prints the target command, and stops serving when you press `ENTER`.

- `Health check`
  Shows stack status, Fleet status, policies, enrollment keys, and enrolled agents.

- `Rebuild lab from scratch (retry trial)`
  Deletes current lab state and redeploys everything from zero.

- `Destroy lab state only`
  Deletes containers, volumes, and generated runtime files without redeploying.

- `Exit`
  Leaves the menu.

## Output Files

Generated files are written under:

```text
runtime/output
```
