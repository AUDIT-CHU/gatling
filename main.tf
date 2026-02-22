terraform {
  required_version = ">= 1.0"

  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

resource "random_string" "proxy_user" {
  length  = 12
  special = false
  upper   = false
}

resource "random_password" "proxy_pass" {
  length  = 24
  special = false
}

provider "hcloud" {
  token = var.hcloud_token
}

resource "hcloud_ssh_key" "main" {
  name       = "${var.server_name}-key"
  public_key = file("${path.module}/ssh/gatling_key.pub")
}

resource "hcloud_firewall" "main" {
  name = "${var.server_name}-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = tostring(var.proxy_port)
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "proxy" {
  name        = var.server_name
  image       = "ubuntu-24.04"
  server_type = var.server_type
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.main.id]
  firewall_ids = [hcloud_firewall.main.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    proxy_port = var.proxy_port
    proxy_user = random_string.proxy_user.result
    proxy_pass = random_password.proxy_pass.result
  })

  labels = {
    purpose = "ipv6-proxy"
    project = "gatling"
  }
}
