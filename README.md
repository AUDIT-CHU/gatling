<p align="center">
  <img src="documentation/gatling.png" alt="Gatling" width="400">
</p>

# Gatling

**IPv6 Rotating Proxy** - Deploy a SOCKS5/HTTP proxy that rotates through 18 quintillion IPv6 addresses per request.

Each outgoing connection uses a random IPv6 from your server's /64 block, making IP-based rate limiting and blocking ineffective.

## How It Works

Hetzner allocates a full /64 IPv6 block (2^64 addresses) to each server. Gatling:

1. Routes the entire /64 to the loopback interface
2. Binds each outgoing connection to a random IPv6 from that range
3. Supports both SOCKS5 and HTTP proxy protocols (auto-detected)
4. Falls back to IPv4 when the target doesn't support IPv6

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Hetzner Cloud](https://hetzner.cloud) account with API token

## Quick Start

```bash
# Clone and configure
git clone https://github.com/youruser/gatling.git
cd gatling

# Generate SSH keys
ssh-keygen -t ed25519 -f ssh/gatling_key -N ""

# Configure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your Hetzner API token

# Deploy
terraform init
terraform apply
```

## Configuration

### Hetzner Token

**Option 1: terraform.tfvars**
```hcl
hcloud_token = "your-token-here"
```

**Option 2: Environment variable**
```bash
export TF_VAR_hcloud_token="your-token-here"
terraform apply
```

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `hcloud_token` | - | Hetzner API token (required) |
| `location` | `nbg1` | Datacenter: `fsn1`, `nbg1`, `hel1` |
| `server_type` | `cpx22` | Server type |
| `server_name` | `gatling-proxy` | Server hostname |
| `proxy_port` | `8080` | Proxy listen port |

## Usage

After deployment, Terraform outputs connection details:

```bash
# View all outputs
terraform output

# Get specific values
terraform output -raw proxy_credentials
terraform output -raw curl_socks5
```

### SOCKS5 Proxy

```bash
# curl
curl --socks5-hostname SERVER_IP:8080 \
     --proxy-user USER:PASS \
     https://api64.ipify.org
```

### Proxychains4

Proxychains4 lets you route any application through the proxy, even if it doesn't natively support proxies.

```bash
# Install
sudo apt install proxychains4

# Configure: edit /etc/proxychains4.conf
# Comment out "proxy_dns" if you want DNS resolved by proxy (IPv6)
# At the bottom, under [ProxyList], add:
socks5 SERVER_IP 8080 USER PASS
```

Usage:

```bash
# Single command
proxychains4 curl https://api64.ipify.org
````

### HTTP Proxy

```bash
curl -x http://USER:PASS@SERVER_IP:8080 https://api64.ipify.org
```

### Test IPv6 Rotation

```bash
# Run 5 requests, each should show a different IPv6
for i in {1..5}; do
  curl -s --socks5-hostname SERVER_IP:8080 \
       --proxy-user USER:PASS \
       https://api64.ipify.org
  echo
done
```

## Server Access

```bash
# SSH access
ssh -i ssh/gatling_key root@SERVER_IP

# View proxy logs
journalctl -u gatling -f

# Service management
systemctl status gatling
systemctl restart gatling
```

## Cleanup

```bash
terraform destroy
```
