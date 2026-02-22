output "server_ipv4" {
  description = "Server public IPv4 address"
  value       = hcloud_server.proxy.ipv4_address
}

output "server_ipv6" {
  description = "Server IPv6 address (first of the /64)"
  value       = hcloud_server.proxy.ipv6_address
}

output "ipv6_network" {
  description = "Full /64 IPv6 block for rotation"
  value       = hcloud_server.proxy.ipv6_network
}

output "ssh_command" {
  description = "SSH command to access the server"
  value       = "ssh -i ssh/gatling_key root@${hcloud_server.proxy.ipv4_address}"
}

output "proxy_credentials" {
  description = "Proxy credentials (user:password)"
  value       = "${random_string.proxy_user.result}:${random_password.proxy_pass.result}"
  sensitive   = true
}

output "proxychains_config" {
  description = "Line to add in /etc/proxychains.conf under [ProxyList]"
  value       = "socks5 ${hcloud_server.proxy.ipv4_address} ${var.proxy_port} ${random_string.proxy_user.result} ${random_password.proxy_pass.result}"
  sensitive   = true
}

output "curl_socks5" {
  description = "Example curl command via SOCKS5 (hostname resolved by proxy = IPv6)"
  value       = "curl --socks5-hostname ${hcloud_server.proxy.ipv4_address}:${var.proxy_port} --proxy-user ${random_string.proxy_user.result}:${random_password.proxy_pass.result} https://api64.ipify.org"
  sensitive   = true
}

output "env_all_proxy" {
  description = "ALL_PROXY environment variable for curl/wget"
  value       = "socks5h://${random_string.proxy_user.result}:${random_password.proxy_pass.result}@${hcloud_server.proxy.ipv4_address}:${var.proxy_port}"
  sensitive   = true
}

output "test_rotation" {
  description = "IPv6 rotation test command"
  value       = "for i in {1..5}; do curl -s --socks5-hostname ${hcloud_server.proxy.ipv4_address}:${var.proxy_port} --proxy-user ${random_string.proxy_user.result}:${random_password.proxy_pass.result} https://api64.ipify.org; echo; done"
  sensitive   = true
}
