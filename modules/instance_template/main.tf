locals {
  network = "${element(split("-", var.subnet), 0)}"
}

resource "google_compute_instance_template" "instance_template" {
  project      = "${var.project}"
  region       = "us-west1"
  name_prefix  = "${local.network}-webserver-template"
  description  = "Template used to create web server instances"
  machine_type = "f1-micro"

  labels = {
    environment = "${local.network}"
  }

  metadata_startup_script = "sudo apt-get update && sudo apt-get install apache2 -y && echo '<html><body><h1>Sandeep Environment: ${local.network}</h1></body></html>' | sudo tee /var/www/html/index.html"

  disk {
      source_image = "debian-cloud/debian-11"
      auto_delete  = true
      boot         = true
  }

  shielded_instance_config {
      enable_secure_boot = true
      enable_vtpm = true
      enable_integrity_monitoring = true
  }

  network_interface {
    subnetwork = "${var.subnet}"
  }

  lifecycle {
    create_before_destroy = true
  }

  # Apply the firewall rule to allow external IPs to access this instance
  tags = ["webserver"]
}
