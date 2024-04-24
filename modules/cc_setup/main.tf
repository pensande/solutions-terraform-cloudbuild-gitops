resource "google_storage_bucket" "input_bucket" {
  project       = var.project
  location      = var.region
  name          = "${var.project}-input-bucket"
  storage_class = "STANDARD"

  uniform_bucket_level_access = true
}

# KMS resources
resource "google_kms_key_ring" "encryption_keyring" {
  project       = var.project
  location      = var.region
  name          = "${var.project}-sym-enc-kr"
}

resource "google_kms_crypto_key" "encryption_key" {
  name          = "${var.project}-sym-enc-key"
  key_ring      = google_kms_key_ring.encryption_keyring.id
  purpose       = "ENCRYPT_DECRYPT"

  version_template {
    algorithm           = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level    = "SOFTWARE"
  }
}

data "google_kms_crypto_key_version" "encryption_key_version" {
  crypto_key = google_kms_crypto_key.encryption_key.id
}

# Service Account
resource "google_service_account" "service_account" {
  project       = var.project
  account_id    = "${var.project}-sa"
  display_name  = "${var.project}-sa"
}

# Artifact Registry repo
resource "google_artifact_registry_repository" "artifact-repo" {
  provider      = google-beta
  project       = var.project
  location      = var.region
  repository_id = "${var.project}-repo"
  description   = "Docker repository confidential space demo"
  format        = "DOCKER"
}
