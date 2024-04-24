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

# IAM entry for service account to operate the cloud-kms key
resource "google_kms_crypto_key_iam_member" "cloud_hsm_key_operator" {
  crypto_key_id = google_kms_crypto_key.encryption_key.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.service_account.email}"
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

data "google_project" "project" {
  project_id = var.project
}

resource "google_iam_workload_identity_pool" "workload_identity_pool" {
  provider                  = google-beta
  project                   = var.project
  workload_identity_pool_id = "${var.project}-pool"
  display_name              = "${var.project}-pool"
  description               = "Identity pool for confidential space demo"
}

# IAM entry for the service account to use the service account of workload identity
resource "google_service_account_iam_member" "workload_identity-role" {
  service_account_id = google_service_account.service_account.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.workload_identity_pool.name}/*"
}
