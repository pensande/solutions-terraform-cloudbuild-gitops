##  Copyright 2023 Google LLC
##  
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##  
##      https://www.apache.org/licenses/LICENSE-2.0
##  
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.


##  This code creates PoC demo environment for Cloud IDS
##  This demo code is not built for production workload ##

resource "google_compute_global_address" "ids_producer_ip_range" {
    project       = var.demo_project_id
    network       = var.vpc_network
    name          = "ids-producer-ip-range"
    description   = "Cloud IDS Producer IP Range"
    purpose       = "VPC_PEERING"
    address_type  = "INTERNAL"
    address       = "192.168.0.0"
    prefix_length = 24
}

resource "google_service_networking_connection" "private_service_access" {
    network                 = var.vpc_network
    service                 = "servicenetworking.googleapis.com"
    reserved_peering_ranges = [google_compute_global_address.ids_producer_ip_range.name]
}

resource "google_cloud_ids_endpoint" "ids_endpoint" {
  project  = var.demo_project_id
  network  = var.vpc_network
  name     = "ids-endpoint-${vpc_subnet}"
  location = "${var.subnetwork_region}-c"
  severity = "INFORMATIONAL"
  
  depends_on = [
    google_compute_global_address.ids_producer_ip_range,
    google_service_networking_connection.private_service_access,
  ]
}

resource "google_compute_packet_mirroring" "ids_packet_mirroring" {
  project     = var.demo_project_id
  region      = var.subnetwork_region
  name        = "ids-packet-mirroring-${vpc_subnet}"
  description = "Packet Mirroring for Cloud IDS"
  network {
    url = var.vpc_network
  }
  mirrored_resources {
    subnetworks {
      url = var.vpc_subnet
    }
  }
  collector_ilb {
    url = google_cloud_ids_endpoint.ids_endpoint.endpoint_forwarding_rule
  }
}

resource "google_service_account" "ids_demo_service_account" {
  project      = var.demo_project_id
  account_id   = "ids-demo-service-account"
  display_name = "Service Account for Cloud IDS Demo"
}

# Create Server Instance
resource "google_compute_instance" "ids_demo_victim_server" {
  project      = var.demo_project_id
  zone         = "${var.subnetwork_region}-c"
  name         = "ids-demo-victim-server"
  machine_type = "e2-micro"
  shielded_instance_config {
    enable_secure_boot = true
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network    = var.vpc_network
    subnetwork = var.vpc_subnet
  }

  service_account {
    email  = google_service_account.ids_demo_service_account.email
    scopes = ["cloud-platform"]
  }
  metadata_startup_script = "apt-get update -y;apt-get install -y nginx;cd /var/www/html/;sudo touch eicar.file"
  labels = {
    asset_type = "victim-machine"
  }
}

# Create Attacker Instance
resource "google_compute_instance" "ids_demo_attacker_machine" {
  project      = var.demo_project_id
  zone         = "${var.subnetwork_region}-c"
  name         = "ids-demo-attacker-machine"
  machine_type = "e2-micro"
  shielded_instance_config {
    enable_secure_boot = true
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network    = var.vpc_network
    subnetwork = var.vpc_subnet
  }

  service_account {
    email  = google_service_account.ids_demo_service_account.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = file("${path.module}/script/startup.sh")
  metadata = {
    TARGET_IP = "${google_compute_instance.ids_demo_victim_server.network_interface.0.network_ip}"
  }

  labels = {
    asset_type = "attacker-machine"
  }

  depends_on = [
    google_compute_instance.ids_demo_victim_server,
    google_compute_packet_mirroring.cloud_ids_packet_mirroring,
  ]
}

# Enable SSH through IAP
resource "google_compute_firewall" "ids_allow_iap_proxy" {
  project   = var.demo_project_id
  network   = var.vpc_network
  name      = "ids-allow-iap-proxy"
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
  target_service_accounts = [
    google_service_account.ids_demo_service_account.email
  ]
}

# Firewall rule to allow icmp & http
resource "google_compute_firewall" "ids_allow_http_icmp" {
  project   = var.demo_project_id
  network   = var.vpc_network
  name      = "ids-allow-http-icmp"
  direction = "INGRESS"
  allow {
    protocol = "tcp"
    ports    = ["80"]
  }
  source_ranges = [var.vpc_subnet_ip]
  target_service_accounts = [
    google_service_account.ids_demo_service_account.email
  ]
  allow {
    protocol = "icmp"
  }
}
