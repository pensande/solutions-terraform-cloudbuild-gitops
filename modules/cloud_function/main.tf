locals {
  cf_zip_archive_name = "cf-${var.function-name}-${data.archive_file.cf_source_zip.output_sha}.zip"
}

data "archive_file" "cf_source_zip" {
  type        = "zip"
  source_dir  = "../../functions/${var.function-name}"
  output_path = "${path.module}/tmp/${var.function-name}.zip"
}

resource "google_storage_bucket_object" "cf_source_zip" {
  name          = local.cf_zip_archive_name
  source        = data.archive_file.cf_source_zip.output_path
  content_type  = "application/zip"
  bucket        = "${var.project}-source-code"
}

resource "google_cloudfunctions_function" "function" {
  project     = var.project
  region      = var.region
  name        = var.function-name
  description = var.function-desc
  runtime     = "python39"
  
  source_archive_bucket = "${var.project}-source-code"
  source_archive_object = google_storage_bucket_object.cf_source_zip.name

  docker_registry       =  "ARTIFACT_REGISTRY"

  trigger_http          = var.triggers == null ? true : null
  ingress_settings      = var.triggers == null ? "ALLOW_ALL" : "ALLOW_INTERNAL_ONLY" 

  dynamic "event_trigger" {
    for_each = var.triggers == null ? [] : var.triggers
    content {
        event_type  = event_trigger.value.event_type
        resource    = event_trigger.value.resource
    }
  }
  
  entry_point           = var.entry-point
  service_account_email = google_service_account.service_account.email

  environment_variables = var.env-vars == null ? null : var.env-vars

  dynamic "secret_environment_variables" {
    for_each = var.secrets == null ? [] : var.secrets
    content {
        key     = secret_environment_variables.value.key
        secret  = secret_environment_variables.value.id
        version = "latest"
    }
  }
}

resource "google_service_account" "service_account" {
  account_id   = "sa-${var.function-name}"
  display_name = "sa-${var.function-name}"
}
