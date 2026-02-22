variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "location" {
  description = "Hetzner datacenter (fsn1 = Falkenstein, nbg1 = Nuremberg, hel1 = Helsinki)"
  type        = string
  default     = "nbg1"
}

variable "server_type" {
  description = "Server type (cpx22 = 2 vCPU/4GB AMD ~5EUR, cpx32 = 4 vCPU/8GB ~9EUR)"
  type        = string
  default     = "cpx22"
}

variable "server_name" {
  description = "Server name"
  type        = string
  default     = "gatling-proxy"
}

variable "proxy_port" {
  description = "Proxy listen port"
  type        = number
  default     = 8080
}
