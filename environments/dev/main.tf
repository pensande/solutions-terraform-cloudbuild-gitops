# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

locals {
  env = "dev"
  source_id = length(google_scc_source.custom_source) > 0 ? split("/","${google_scc_source.custom_source[0].id}")[3] : null
  scc_config = jsonencode(   
		{
			"name" : "scc",
			"organization_id" : var.organization, 
	    "source_id": local.source_id,
			"source_name" : "Acalvio Shadowplex-${random_string.depname.result}"
		}
  )
  null_scc_config = jsonencode({})
}

provider "google" {
  project = var.project
}

module "vpc" {
  source            = "../../modules/vpc"
  project           = var.project
  env               = local.env
  region            = var.region
  secondary_ranges  = {
    "${local.env}-subnet-01" = [
        {
            range_name      = "cluster-ipv4-cidr-block"
            ip_cidr_range   = "10.224.0.0/14"
        },
        {
            range_name      = "services-ipv4-cidr-block"
            ip_cidr_range   = "10.228.0.0/20"
        }
    ]
  }
}

module "cloud_nat" {
  source  = "../../modules/cloud_nat"
  project = var.project
  network = module.vpc.name
  region  = var.region
}

module "gke_cluster" {
    count           = var.create_dev_gke_cluster ? 1 : 0
    source          = "../../modules/gke_cluster"
    cluster_name    = "${local.env}-binauthz"
    project         = var.project
    region          = var.region
    network         = module.vpc.id
    subnetwork      = module.vpc.subnet
    master_ipv4_cidr= "10.${local.env == "dev" ? 10 : 20}.1.16/28"
    
    depends_on = [
      google_compute_security_policy.armor_waf_security_policy
    ]
}

# Workload Identity for the Kubernetes Cluster
resource "google_service_account" "k8s_app_service_account" {
  account_id   = "sa-k8s-app"
  display_name = "Service Account For Workload Identity"
}

# IAM entry for k8s service account to use the service account of workload identity
resource "google_service_account_iam_member" "workload_identity-role" {
  service_account_id = google_service_account.k8s_app_service_account.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project}.svc.id.goog[default/my-k8s-app]"
}

resource "google_secret_manager_secret" "mysql-root-password" {
  project   = var.project
  secret_id = "mysql-root-password"

  replication {
    automatic = true
  }
}

# IAM entry for service account of workload identity to use the mysql-root-password secret
resource "google_secret_manager_secret_iam_binding" "mysql_root_password_secret_binding" {
  project   = google_secret_manager_secret.mysql-root-password.project
  secret_id = google_secret_manager_secret.mysql-root-password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  members    = [
      "serviceAccount:${google_service_account.k8s_app_service_account.email}",
  ]
}

# Artifact Registry repo for binauthz-demo
resource "google_artifact_registry_repository" "binauthz-demo-repo" {
  provider      = google-beta
  project       = var.project

  location      = var.region
  repository_id = "binauthz-demo-repo"
  description   = "Docker repository for binauthz demo"
  format        = "DOCKER"
}

resource "google_compute_global_address" "lb_ip_address" {
  name          = "dev-lb-static-ip"
  project       = var.project
}
/*
resource "google_recaptcha_enterprise_key" "recaptcha_test_site_key" {
  provider      = google-beta
  display_name  = "recaptcha-test-site-key"
  project       = var.demo_project

  testing_options {
    testing_score = 0.5
  }

  web_settings {
    integration_type  = "SCORE"
    allow_all_domains = false
    allow_amp_traffic = false
    allowed_domains   = ["agarsand.demo.altostrat.com"]
  }
}

resource "google_recaptcha_enterprise_key" "recaptcha_redirect_site_key" {
  provider      = google-beta
  display_name  = "recaptcha-redirect-site-key"
  project       = var.demo_project

  web_settings {
    integration_type              = "INVISIBLE"
    allow_all_domains             = false
    allowed_domains               = ["agarsand.demo.altostrat.com"]
    challenge_security_preference = "USABILITY"
  }
}
*/
# Cloud Armor WAF Policy for Dev Backends
resource "google_compute_security_policy" "armor_waf_security_policy" {
  count         = var.create_dev_gke_cluster || var.create_iap_run_sql_demo ? 1 : 0
  provider      = google-beta
  name          = "armor-waf-security-policy"
  description   = "Cloud Armor Security Policy"
  project       = var.project
  type          = "CLOUD_ARMOR"

  recaptcha_options_config {
    redirect_site_key = var.recaptcha_site_key
  }

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }

  rule {
    action   = "deny(403)"
    priority = "3000"
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1})"
      }
    }
    description = "Allow only Indians. Mera Bharat Mahan! :)"
  }

  rule {
    action   = "deny(403)"
    priority = "6000"
    match {
      expr {
        expression = "origin.region_code != 'IN'"
      }
    }
    description = "Allow only users from India. Mera Bharat Mahan! :)"
  }

  rule {
    action   = "redirect"
    priority = "7000"
    
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["104.132.232.68/32"]
      }
    }

    redirect_options {
        type = "EXTERNAL_302"
        target = "https://www.agarsand.demo.altostrat.com/denied.html"
    }

    description = "Deny access to IPs"
  }

  rule {
    action   = "allow"
    priority = "8000"
    match {
      expr {
        expression = "request.path.matches('good-score.html') && token.recaptcha_session.score > 0.4"
      }
    }
    description = "Allow if the recaptcha session score is above threshold"
  }

  rule {
    action   = "deny(403)"
    priority = "9000"
    match {
      expr {
        expression = "request.path.matches('bad-score.html') && token.recaptcha_session.score < 0.6"
      }
    }
    description = "Deny if the recaptcha session score is below threshold"
  }

  rule {
    action   = "redirect"
    priority = "10000"
    match {
      expr {
        expression = "request.path.matches('median-score.html') && token.recaptcha_session.score == 0.5"
      }
    }
    redirect_options {
      type = "GOOGLE_RECAPTCHA"
    }
    description = "Redirect to challenge page if the recaptcha session score is between thresholds"
  }

  rule {
    action   = "throttle"
    priority = "11000"
    match {
      expr {
        expression = "request.headers['host'].lower().contains('gke.agarsand.demo.altostrat.com')"
      }
    }
    rate_limit_options {
        conform_action  = "allow"
        exceed_action   = "deny(429)"

        enforce_on_key  = "ALL"

        rate_limit_threshold {
            count           = 5
            interval_sec    = 60
        }
    }
    description = "Rate-based Throttle"
  }

  rule {
    action      = "rate_based_ban"
    priority    = "12000"
    match {
      expr {
        expression = "request.headers['host'].lower().matches('owasp.agarsand.demo.altostrat.com')"
      }
    }
    rate_limit_options {
        conform_action  = "allow"
        exceed_action   = "deny(429)"

        enforce_on_key  = "ALL"

        rate_limit_threshold {
            count           = 10
            interval_sec    = 60
        }

        ban_duration_sec    = 300
    }
    description = "Rate-based Throttle"
    preview     = true
  }
}

############################
## Website Storage Bucket ##
############################

resource "google_storage_bucket" "www" {
 project       = var.project
 name          = "www.agarsand.demo.altostrat.com"
 location      = "US"
 storage_class = "STANDARD"

 uniform_bucket_level_access = true

 website {
    main_page_suffix = "index.html"
    not_found_page   = "denied.html"
  }
}

# IAM entry for the bucket to make it publicly readable
resource "google_storage_bucket_iam_member" "member" {
  bucket    = google_storage_bucket.www.id
  role      = "roles/storage.objectViewer"
  member    = "allUsers"
} 

# Upload html and image files as objects to the bucket
resource "google_storage_bucket_object" "index_html" {
 name         = "index.html"
 source       = "../../www/index.html"
 content_type = "text/html"
 bucket       = google_storage_bucket.www.id
}

resource "google_storage_bucket_object" "denied_html" {
 name         = "denied.html"
 source       = "../../www/denied.html"
 content_type = "text/html"
 bucket       = google_storage_bucket.www.id
}

resource "google_storage_bucket_object" "denied_png" {
 name         = "denied.png"
 source       = "../../www/denied.png"
 content_type = "image/jpeg"
 bucket       = google_storage_bucket.www.id
}

##############################
## Pulumi Related Resources ##
##############################

resource "google_secret_manager_secret" "pulumi_access_token" {
  project   = var.project
  secret_id = "pulumi-access-token"

  replication {
    automatic = true
  }
}

####################################
## IAP, Cloud Run, Cloud SQL Demo ##
####################################

# reserved public ip address
resource "google_compute_global_address" "iap_run_sql_demo" {
  name          = "iap-run-sql-demo"
  project       = var.project
}

# ssl certificate
resource "google_compute_managed_ssl_certificate" "iap_run_sql_demo_cert" {
  name = "iap-run-sql-demo-certificate"

  managed {
    domains = ["run.agarsand.demo.altostrat.com."]
  }
}

# forwarding rule
resource "google_compute_global_forwarding_rule" "https" {
  count                 = var.create_iap_run_sql_demo ? 1 : 0
  project               = var.project
  name                  = "iap-run-sql-demo-https-fw-rule"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.iap_run_sql_demo[0].id
  ip_address            = google_compute_global_address.iap_run_sql_demo.id
}

# https proxy
resource "google_compute_target_https_proxy" "iap_run_sql_demo" {
  count       = var.create_iap_run_sql_demo ? 1 : 0
  name        = "iap-run-sql-demo"
  url_map     = google_compute_url_map.iap_run_sql_demo[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.iap_run_sql_demo_cert.id]
}

# url map
resource "google_compute_url_map" "iap_run_sql_demo" {
  count             = var.create_iap_run_sql_demo ? 1 : 0
  name              = "iap-run-sql-demo-url-map"
  description       = "iap-enabled gclb for the iap-run-sql-demo"
  default_service   = google_compute_backend_service.iap_run_sql_demo_backend[0].id

  host_rule {
    hosts        = ["run.agarsand.demo.altostrat.com"]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.iap_run_sql_demo_backend[0].id
  }
}

# backend service
resource "google_compute_backend_service" "iap_run_sql_demo_backend" {
  count                 = var.create_iap_run_sql_demo ? 1 : 0
  project               = var.project            
  name                  = "iap-run-sql-demo-serverless-backend"
  port_name             = "http"
  protocol              = "HTTP"
  enable_cdn            = false
  security_policy       = google_compute_security_policy.armor_waf_security_policy[0].id

  backend {
    group               = google_compute_region_network_endpoint_group.iap_run_sql_demo_neg[0].id
  }

  log_config {
    enable              = true
  }

  iap {
    oauth2_client_id     = google_iap_client.iap_run_sql_demo_client[0].client_id
    oauth2_client_secret = google_iap_client.iap_run_sql_demo_client[0].secret
  }
}

# network endpoint group
resource "google_compute_region_network_endpoint_group" "iap_run_sql_demo_neg" {
  count                 = var.create_iap_run_sql_demo ? 1 : 0
  name                  = "iap-run-sql-demo-neg"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  cloud_run {
    service = google_cloud_run_service.iap_run_service[0].name
  }
}

# cloud run service
resource "google_cloud_run_service" "iap_run_service" {
  count     = var.create_iap_run_sql_demo ? 1 : 0
  name      = "iap-run-sql-demo"
  location  = var.region

  template {
    spec {
      containers {
        image   = "us-central1-docker.pkg.dev/secops-project-348011/binauthz-demo-repo/iap-run-sql-demo@sha256:b8aa54d57d515d91e9524df4b99295e7946eb0a0015b8d7abf9af31b6664d741"
        ports {
          container_port = 8080
        }
      }
      service_account_name = google_service_account.run_sql_service_account[0].email
    }
    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale"      = "2"
        "run.googleapis.com/cloudsql-instances" = google_sql_database_instance.iap_run_sql_demo_db_instance[0].connection_name
        "run.googleapis.com/client-name"        = "terraform"
      }
    }
  }

  metadata {
    annotations = {
      "run.googleapis.com/ingress"            = "internal-and-cloud-load-balancing"
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  lifecycle {
    ignore_changes = [
      metadata[0].annotations,
    ]
  }
}

resource "google_sql_database" "iap_run_sql_demo_database" {
  count     = var.create_iap_run_sql_demo ? 1 : 0
  name      = "iap-run-sql-demo-db"
  instance  = google_sql_database_instance.iap_run_sql_demo_db_instance[0].name
}

resource "google_sql_database_instance" "iap_run_sql_demo_db_instance" {
  count             = var.create_iap_run_sql_demo ? 1 : 0
  name              = "iap-run-sql-demo-db-instance"
  region            = var.region
  database_version  = "POSTGRES_14"
  settings {
    tier            = "db-f1-micro"

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    ip_configuration {
      ipv4_enabled  = true
      require_ssl   = false
    }
  }

  deletion_protection  = "false"
}

# service account for cloud run
resource "google_service_account" "run_sql_service_account" {
  count         = var.create_iap_run_sql_demo ? 1 : 0
  account_id    = "sa-iap-run-sql-demo"
  display_name  = "sa-iap-run-sql-demo"
}

resource "google_sql_user" "db_user" {
  count         = var.create_iap_run_sql_demo ? 1 : 0
  name          = trimsuffix(google_service_account.run_sql_service_account[0].email, ".gserviceaccount.com")
  instance      = google_sql_database_instance.iap_run_sql_demo_db_instance[0].name
  type          = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_project_iam_member" "sql_user_policy" {
  count         = var.create_iap_run_sql_demo ? 1 : 0
  project       = var.project
  role          = "roles/cloudsql.instanceUser"
  member        = "serviceAccount:${google_service_account.run_sql_service_account[0].email}"
} 

resource "google_project_iam_member" "sql_client_policy" {
  count         = var.create_iap_run_sql_demo ? 1 : 0
  project       = var.project
  role          = "roles/cloudsql.client"
  member        = "serviceAccount:${google_service_account.run_sql_service_account[0].email}"
}

#oauth2 client
resource "google_iap_client" "iap_run_sql_demo_client" {
  count         = var.create_iap_run_sql_demo ? 1 : 0
  display_name  = "IAP Run SQL Demo Client"
  brand         =  "projects/${var.project}/brands/${data.google_project.project.number}"
}

# Allow users secure access to the iap-run-sql-demo app
resource "google_iap_web_backend_service_iam_member" "iap_run_sql_demo_member" {
  count                 = var.create_iap_run_sql_demo ? 1 : 0
  project               = var.project
  web_backend_service   = google_compute_backend_service.iap_run_sql_demo_backend[0].name
  role                  = "roles/iap.httpsResourceAccessor"
  member                = "user:${var.iap_user}"
  condition {
    expression          = "\"accessPolicies/${google_access_context_manager_access_policy.access_policy.name}/accessLevels/windows_encrypted\" in request.auth.access_levels"
    title               = "beyondcorp_access_level"    
    description         = "enforce beyondcorp access level windows_encrypted"
  } 
}

# Allow IAP to invoke the cloud run service
resource "google_project_service_identity" "iap_sa" {
  count     = var.create_iap_run_sql_demo ? 1 : 0
  provider  = google-beta
  project   = var.project
  service   = "iap.googleapis.com"
}

resource "google_cloud_run_service_iam_member" "run_all_users" {
  count     = var.create_iap_run_sql_demo ? 1 : 0
  service   = google_cloud_run_service.iap_run_service[0].name
  location  = google_cloud_run_service.iap_run_service[0].location
  role      = "roles/run.invoker"
  member    = "serviceAccount:${google_project_service_identity.iap_sa[0].email}"
}

######################################
## BeyondCorp with IAP-RUN_SQL Demo ##
######################################

data "google_project" "project" {
  project_id    = var.project  
}

resource "google_access_context_manager_access_policy" "access_policy" {
  parent = "organizations/${var.organization}"
  title  = "Access Policy for IAP Demo"
}

resource "google_access_context_manager_access_level" "access_level" {
  parent = "accessPolicies/${google_access_context_manager_access_policy.access_policy.name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.access_policy.name}/accessLevels/india"
  title  = "india_region"
  basic {
    conditions {
      regions = [
        "IN",
      ]
    }
  }

  lifecycle {
    ignore_changes = [basic.0.conditions]
  }
}

resource "google_access_context_manager_access_level_condition" "access_level_conditions" {
  access_level = google_access_context_manager_access_level.access_level.name
  ip_subnetworks = ["192.0.4.0/24"]
  negate = false
}

#################################################
## GKE Security Posture Dashboard with BQ Demo ##
#################################################

# A BigQuery dataset to store logs in
resource "google_bigquery_dataset" "gke_security_posture_dataset" {
  project           = var.project
  location          = var.region
  dataset_id        = "gke_security_posture_dataset"
  friendly_name     = "gke_security_posture_dataset"
  description       = "Logging and tracking vulnerability findings reported by GKE Security Posture"
}

# Sink to send logs related to gke security posture vulnerability findings
resource "google_logging_project_sink" "gke_security_posture_sink" {
  project       = var.project
  name          = "gke-security-posture-sink"
  description   = "log sink to send vulnerabilities identified by gke_security_posture"
  destination   = "bigquery.googleapis.com/${google_bigquery_dataset.gke_security_posture_dataset.id}"
  filter        = "resource.type=\"k8s_cluster\" jsonPayload.@type=\"type.googleapis.com/cloud.kubernetes.security.containersecurity_logging.Finding\" jsonPayload.type=\"FINDING_TYPE_VULNERABILITY\""

  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }
}

# Write access for the sink's identity to write logs to the bq dataset
resource "google_bigquery_dataset_iam_member" "dataset_iam_member" {
  dataset_id = google_bigquery_dataset.gke_security_posture_dataset.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "${google_logging_project_sink.gke_security_posture_sink.writer_identity}"
}

####################
## Cloud IDS Demo ##
####################

module "cloud_ids" {
  count             = var.create_ids_demo ? 1 : 0
  source            = "../../modules/cloud_ids"
  demo_project_id   = var.project
  subnetwork_region = var.region
  vpc_network       = module.vpc.id
  vpc_subnet        = module.vpc.subnet
  vpc_subnet_ip     = module.vpc.subnet_ip
}

####################################
## Security CTF FireStore Backend ##
####################################

# Enables Firebase services for the new project created above.
resource "google_firebase_project" "firestore" {
  provider = google-beta
  project  = var.project
}

# Provisions the Firestore database instance.
resource "google_firestore_database" "firestore" {
  provider          = google-beta
  project           = var.project
  name              = "security-ctf"
  location_id       = "nam5"
  type              = "FIRESTORE_NATIVE"
  concurrency_mode  = "OPTIMISTIC"

  depends_on = [
    google_firebase_project.firestore,
  ]
}

# Creates a ruleset of Firestore Security Rules from a local file.
resource "google_firebaserules_ruleset" "firestore" {
  provider = google-beta
  project  = var.project
  source {
    files {
      name = "firestore.rules"
      content = "service cloud.firestore {match /databases/{database}/documents { match /{document=**} { allow read, write: if false; } } }"
    }
  }

  depends_on = [
    google_firestore_database.firestore,
  ]
}

# Releases the ruleset for the Firestore instance.
resource "google_firebaserules_release" "firestore" {
  provider     = google-beta
  name         = "cloud.firestore.new" # must be cloud.firestore
  ruleset_name = google_firebaserules_ruleset.firestore.name
  project      = var.project

  depends_on = [
    google_firestore_database.firestore,
  ]
}

# Creates a Firebase Web App in the new project created above.
resource "google_firebase_web_app" "security_ctf_app" {
  provider     = google-beta
  project      = var.project
  display_name = "Security CTF App"

  deletion_policy = "DELETE"

  # Wait for Firebase to be enabled in the Google Cloud project before creating this App.
  depends_on = [
    google_firebase_project.firestore,
  ]
}

############################
## Config Controller Demo ##
############################

# solution-demos-project
data "google_project" "solution_demos_project" {
  project_id    = var.demo_project  
}

# Allow the Config Controller service agent to manage buckets
resource "google_project_iam_member" "config_control_bucket_admin" {
  project       = var.project
  role          = "roles/storage.admin"
  member        = "serviceAccount:service-${data.google_project.solution_demos_project.number}@gcp-sa-yakima.iam.gserviceaccount.com"
} 

# Allow the Config Controller service agent to manage pub/sub
resource "google_project_iam_member" "config_control_pubsub_admin" {
  project       = var.project
  role          = "roles/pubsub.admin"
  member        = "serviceAccount:service-${data.google_project.solution_demos_project.number}@gcp-sa-yakima.iam.gserviceaccount.com"
} 

# Allow the Config Controller service agent to manage roles
resource "google_project_iam_member" "config_control_role_admin" {
  project       = var.project
  role          = "roles/iam.roleAdmin"
  member        = "serviceAccount:service-${data.google_project.solution_demos_project.number}@gcp-sa-yakima.iam.gserviceaccount.com"
}

# Allow the Config Controller service agent to consume services
resource "google_project_iam_member" "config_control_service_user" {
  project       = var.demo_project
  role          = "roles/serviceusage.serviceUsageConsumer"
  member        = "serviceAccount:service-${data.google_project.solution_demos_project.number}@gcp-sa-yakima.iam.gserviceaccount.com"
}

#############################
## Confidential Space Demo ##
#############################

module "primus_services" {
  source    = "../../modules/cc_setup"
  project   = var.primus_project
  region    = var.region
  file_name = "primus_customer_list.csv"
}

module "secundus_services" {
  source    = "../../modules/cc_setup"
  project   = var.secundus_project
  region    = var.region
  file_name = "secundus_customer_list.csv"
}

resource "google_storage_bucket" "result_bucket" {
  project       = var.secundus_project
  location      = var.region
  name          = "${var.secundus_project}-result-bucket"
  storage_class = "STANDARD"

  uniform_bucket_level_access = true
}

# Workload Service Account for Secundus Bank
resource "google_service_account" "workload_service_account" {
  project       = var.secundus_project
  account_id    = "cc-demo-workload-sa"
  display_name  = "cc-demo-workload-sa"
}

# IAM entry for Workload Service Account to read data from Primus storage bucket
resource "google_storage_bucket_iam_member" "read_primus_bucket" {
  bucket  = "${module.primus_services.input_bucket}"
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.workload_service_account.email}"
}

# IAM entry for Workload Service Account to read data from Secundus storage bucket
resource "google_storage_bucket_iam_member" "read_secundus_bucket" {
  bucket  = "${module.secundus_services.input_bucket}"
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.workload_service_account.email}"
}

# IAM entry for Workload Service Account to write data to Secundus result bucket
resource "google_storage_bucket_iam_member" "write_result_bucket" {
  bucket  = google_storage_bucket.result_bucket.name
  role    = "roles/storage.objectCreator"
  member  = "serviceAccount:${google_service_account.workload_service_account.email}"
}

# IAM entry for Workload Service Account to write logs
resource "google_project_iam_member" "log_writer" {
  project = var.secundus_project
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.workload_service_account.email}"
}

# IAM entry for Workload Service Account to generate an attestation token
resource "google_project_iam_member" "cc_workload_user" {
  project = var.secundus_project
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.workload_service_account.email}"
}

# IAM entry for Workload Service Account to read from the Primus Artifact Registry repo
resource "google_artifact_registry_repository_iam_member" "primus_ar_reader" {
  provider    = google-beta
  project     = var.primus_project
  location    = var.region
  repository  = "${module.primus_services.repo_name}"
  role        = "roles/artifactregistry.reader"
  member      = "serviceAccount:${google_service_account.workload_service_account.email}"
}

# IAM entry for pensande user to write to the Primus Artifact Registry repo
resource "google_artifact_registry_repository_iam_member" "primus_ar_writer" {
  provider    = google-beta
  project     = var.primus_project
  location    = var.region
  repository  = "${module.primus_services.repo_name}"
  role        = "roles/artifactregistry.writer"
  member      = "user:${var.iap_user}"
}

resource "google_iam_workload_identity_pool_provider" "primus_pool_provider" {
  provider                           = google-beta
  project                            = var.primus_project
  workload_identity_pool_id          = "${module.primus_services.pool_id}"
  workload_identity_pool_provider_id = "${var.primus_project}-provider"
  display_name                       = "${var.primus_project}-provider"
  description                        = "Identity pool provider for confidential space demo"
  attribute_condition                = "assertion.swname == 'CONFIDENTIAL_SPACE' && 'STABLE' in assertion.submods.confidential_space.support_attributes && assertion.submods.container.image_reference == '${var.region}-docker.pkg.dev/${var.primus_project}/${module.primus_services.repo_name}/workload-container:latest' && '${google_service_account.workload_service_account.email}' in assertion.google_service_accounts"
  attribute_mapping                  = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    allowed_audiences = ["https://sts.googleapis.com"]
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
  }
}

resource "google_iam_workload_identity_pool_provider" "secundus_pool_provider" {
  provider                           = google-beta
  project                            = var.secundus_project
  workload_identity_pool_id          = "${module.secundus_services.pool_id}"
  workload_identity_pool_provider_id = "${var.secundus_project}-provider"
  display_name                       = "${var.secundus_project}-provider"
  description                        = "Identity pool provider for confidential space demo"
  attribute_condition                = "assertion.swname == 'CONFIDENTIAL_SPACE' && 'STABLE' in assertion.submods.confidential_space.support_attributes && assertion.submods.container.image_digest == '${var.cc_image_digest}' && assertion.submods.container.image_reference == '${var.region}-docker.pkg.dev/${var.primus_project}/${module.primus_services.repo_name}/workload-container:latest' && '${google_service_account.workload_service_account.email}' in assertion.google_service_accounts"
  attribute_mapping                  = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    allowed_audiences = ["https://sts.googleapis.com"]
    issuer_uri        = "https://confidentialcomputing.googleapis.com/"
  }
}

module "secundus_vpc" {
  source  = "../../modules/vpc"
  project = var.secundus_project
  region  = var.region
  env     = "cc-demo-workload"
  secondary_ranges  = {
    "cc-demo-workload-subnet-01" = [
        {
            range_name      = "random"
            ip_cidr_range   = "10.224.0.0/14"
        }
    ]
  }
}

# disable org policy to create VMs using confidential space image
resource "google_org_policy_policy" "disable_trusted_image_projects" {
  name   = "projects/${var.secundus_project}/policies/compute.trustedImageProjects"
  parent = "projects/${var.secundus_project}"

  spec {
    inherit_from_parent = false
    reset               = true
  }
}

# wait after disabling org policy
resource "time_sleep" "wait_disable_trusted_image_projects" {
  depends_on       = [google_org_policy_policy.disable_trusted_image_projects]
  create_duration  = "30s"
}

resource "google_compute_instance" "first_workload_cvm" {
  count                     = var.create_cc_demo ? 1 : 0
  project                   = var.secundus_project
  name                      = "first-workload-cvm"
  machine_type              = "n2d-standard-2"
  zone                      = "${var.region}-a"
  
  allow_stopping_for_update = true

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  confidential_instance_config {
    enable_confidential_compute = true
  }

  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  boot_disk {
    auto_delete = true
    initialize_params {
      image = "confidential-space-images/confidential-space"
    }
  }

  network_interface {
    network    = module.secundus_vpc.name
    subnetwork = module.secundus_vpc.subnet
  }

  service_account {
    email  = google_service_account.workload_service_account.email
    scopes = ["cloud-platform"]
  }
  
  metadata = {
    tee-image-reference = "${var.region}-docker.pkg.dev/${var.primus_project}/${module.primus_services.repo_name}/workload-container:latest"
    tee-restart-policy  = "Never"
    tee-cmd             = "[\"count-location\",\"Seattle\",\"gs://${google_storage_bucket.result_bucket.name}/seattle-result\"]"
  }

  depends_on = [time_sleep.wait_disable_trusted_image_projects]
}

resource "google_compute_instance" "second_workload_cvm" {
  count                     = var.create_cc_demo ? 1 : 0
  project                   = var.secundus_project
  name                      = "second-workload-cvm"
  machine_type              = "n2d-standard-2"
  zone                      = "${var.region}-a"
  
  allow_stopping_for_update = true

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  confidential_instance_config {
    enable_confidential_compute = true
  }

  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  boot_disk {
    auto_delete = true
    initialize_params {
      image = "confidential-space-images/confidential-space"
    }
  }

  network_interface {
    network    = module.secundus_vpc.name
    subnetwork = module.secundus_vpc.subnet
  }

  service_account {
    email  = google_service_account.workload_service_account.email
    scopes = ["cloud-platform"]
  }
  
  metadata = {
    tee-image-reference = "${var.region}-docker.pkg.dev/${var.primus_project}/${module.primus_services.repo_name}/workload-container:latest"
    tee-restart-policy  = "Never"
    tee-cmd             = "[\"list-common-customers\",\"gs://${google_storage_bucket.result_bucket.name}/list-common-result\"]"
  }

  depends_on = [time_sleep.wait_disable_trusted_image_projects]
}

#####################################
## Vertex AI Security Posture Demo ##
#####################################
/*
resource "google_securityposture_posture" "vertex_ai_posture" {
  provider      = google-beta
  posture_id  = "vertex_ai_posture"
  parent      = "organizations/${var.organization}"
  location    = "global"
  state       = "ACTIVE"
  description = "security posture demo for vertex ai"
  policy_sets {
    policy_set_id = "org_policy_set"
    description   = "set of org policies"
    policies {
      policy_id = "policy_1"
      constraint {
        org_policy_constraint {
          canned_constraint_id = "storage.uniformBucketLevelAccess"
          policy_rules {
              enforce = true
          }
        }
      }
    }
  }
}

resource "google_securityposture_posture_deployment" "vertexai_posture_deployment" {
  provider              = google-beta
  posture_deployment_id = "vertexai_posture_deployment"
  parent                = "organizations/${var.organization}"
  location              = "global"
  description           = "vertex ai security posture deployment"
  target_resource       = "projects/${var.project}"
  posture_id            = google_securityposture_posture.vertex_ai_posture.name
  posture_revision_id   = google_securityposture_posture.vertex_ai_posture.revision_id
}
*/

#########################
## Active Defense Demo ##
#########################

data "google_compute_subnetwork" "my-subnetwork" {
  name    = var.subnet_name
  region  = var.subnet_region
  project = var.deception_project
}
resource "google_project_iam_audit_config" "audit_logs" {
  depends_on = [
    null_resource.predeploy
  ]
  project = var.deception_project
  service = "storage.googleapis.com"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
//1
resource "null_resource" "predeploy" {
  /*provisioner "local-exec" {
    command = <<-EOT
      "predeploy.py --adc_url_hash ${var.adc_url_hash} --session_id ${var.session_id} --service_account ${var.dep_service_account} --adc_lb_address ${var.adc_lb_address}"
    EOT
    interpreter = ["python3", "-m"]
  }*/
}
//8
resource "random_string" "depname" {
  depends_on = [
    null_resource.predeploy
  ]
  length           = 8
  special          = false
  upper            = false
  lower            = true
}
//9
resource "google_compute_address" "static_ip_address" {
  project = var.deception_project
  name    = "sensor-${random_string.depname.result}-addr"
  region  = var.subnet_region
}
//10
resource "google_service_account" "sensor_service_account" {
  project      = var.deception_project
  account_id   = "sensor-${random_string.depname.result}"
  display_name = "Sensor Service Account"
}
//11
resource "google_project_iam_member" "sensor_iam1" {
  project = var.deception_project
  role    = "roles/compute.instanceAdmin"
  member  = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}
//12
resource "google_project_iam_member" "sensor_iam2" {
  project = var.deception_project
  role    = "roles/compute.networkUser"
  member  = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}
//13
resource "google_project_iam_member" "sensor_iam3" {
  project = var.deception_project
  role    = "roles/logging.privateLogViewer"
  member  = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}
//14
resource "google_project_iam_member" "sensor_iam4" {
  project = var.deception_project
  role    = "roles/iam.serviceAccountKeyAdmin"
  member  = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}
//15
resource "google_project_iam_member" "sensor_iam5" {
  project = var.deception_project
  role    = "roles/storage.admin"
  member  = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}
//16
resource "google_organization_iam_member" "sensor_iam6" {
  org_id  = "${var.organization}"
  role    = "roles/securitycenter.admin"
  member  = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}
//17
resource "google_service_account_iam_member" "sensor_on_nano" {
  service_account_id = google_service_account.nano_sensor_service_account.id
  role               = "roles/iam.serviceAccountUser"
  member             = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}
//18
resource "google_service_account" "nano_sensor_service_account" {
  project      = var.deception_project
  account_id   = "nano-sensor-${random_string.depname.result}"
  display_name = "Nano Service Account"
}
//19
resource "google_compute_firewall" "sensor_firewall_0" {
  name    = "shadowplex-decoy-${random_string.depname.result}"
  project = var.host_project 
  network = var.vpc

  source_ranges = var.source_ranges //variable
  target_service_accounts = [ "${google_service_account.nano_sensor_service_account.email}" ]
  allow {
    protocol = "all"
  }
}

resource "google_compute_firewall" "sensor_firewall_1" {
  name    = "shadowplex-bcde-${random_string.depname.result}"
  project = var.host_project
  network = var.vpc

  source_ranges = var.source_ranges //variable
  target_service_accounts = [ "${google_service_account.sensor_service_account.email}" ]
  allow {
    protocol = "tcp"
    ports = ["443"]
  }
}
//20
resource "google_compute_firewall" "sensor_firewall_2" {
  name    = "shadowplex-sting-${random_string.depname.result}"
  project = var.host_project
  network = var.vpc

  source_service_accounts = [ "${google_service_account.sensor_service_account.email}" ]
  allow {
    protocol = "all"
  }
}
//21
resource "google_compute_firewall" "sensor_firewall_3" {
  name    = "shadowplex-vxlan-${random_string.depname.result}"
  project = var.host_project
  network = var.vpc

  source_service_accounts = [ "${google_service_account.nano_sensor_service_account.email}" ]
  target_service_accounts = [ "${google_service_account.sensor_service_account.email}" ]
  allow {
    protocol = "udp"
    ports = ["4789"]
  }
}
#2
resource "google_project_service" "enable_compute" {
  depends_on = [
    null_resource.predeploy
  ]
  project = var.deception_project
  service = "compute.googleapis.com"
  disable_on_destroy = false
}
//3
resource "google_project_service" "enable_storage-component" {
  depends_on = [
    null_resource.predeploy
  ]
  project = var.deception_project
  service = "storage-component.googleapis.com"
  disable_on_destroy = false
}
//4
resource "google_project_service" "enable_storage-api" {
  depends_on = [
    null_resource.predeploy
  ]
  project = var.deception_project
  service = "storage-api.googleapis.com"
  disable_on_destroy = false
}
//5
resource "google_project_service" "enable_iam" {
  depends_on = [
    null_resource.predeploy
  ]
  project = var.deception_project
  service = "iam.googleapis.com"
  disable_on_destroy = false
}
//6
resource "google_project_service" "enable_securitycenter" {
  depends_on = [
    null_resource.predeploy
  ]
  project = var.deception_project
  service = "securitycenter.googleapis.com"
  disable_on_destroy = false
  count = "0"
  //count = "${var.enable_securitycenter == "No" ? 0 : 1}"

}
//7
resource "google_project_service" "enable_cloudresourcemanager" {
  depends_on = [
    null_resource.predeploy
  ]
  project = var.deception_project
  service = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
  count = "0"
  //count = "${var.enable_cloudresourcemanager == "No" ? 0 : 1}"

}
//23

resource "google_org_policy_policy" "disable_shielded_vm" {
  name   = "projects/${var.deception_project}/policies/compute.requireShieldedVm"
  parent = "projects/${var.deception_project}"

  spec {
    inherit_from_parent = false
    reset               = true
  }
}

resource "google_org_policy_policy" "update_trusted_projects" {
  name   = "projects/${var.deception_project}/policies/compute.trustedImageProjects"
  parent = "projects/${var.deception_project}"

  spec {
    inherit_from_parent = true

    rules {
      values {
        allowed_values = ["projects/${var.image_project}"]
      }
    }
  }
}

# wait after disabling org policies
resource "time_sleep" "wait_disable_org_policies" {
  depends_on       = [google_org_policy_policy.disable_shielded_vm, google_org_policy_policy.update_trusted_projects]
  create_duration  = "60s"
}

resource "google_compute_instance" "sensor_vm" {
  name         = "sensor-${random_string.depname.result}"
  machine_type = "e2-standard-2"
  zone         = var.zonename
  project      = var.deception_project
  
  allow_stopping_for_update = true

  metadata = {
    "sensor_config" = jsonencode(
      {
          "adc_ip_address" = var.adc_ip_address //local
          "adc_lb_address" = var.adc_lb_address //local
          "spa_server" = var.adc_lb_address //local
          "sensor_type" = "vpc"
          "sensor_svc_acct" = google_service_account.sensor_service_account.email
          "nano_svc_acct" = google_service_account.nano_sensor_service_account.email
          "deception_project" =  var.deception_project//input
          "host_project" = var.host_project//input
          "image_project" = var.image_project//local
          "service_projects" = [var.host_project,]
          "vpc_name" = var.vpc //input
          "nano_sensor_image_name" = "nano-sensor-${var.sensor_version}"
      }
    )
	  "scc_config" = var.configure_cscc ? local.scc_config : local.null_scc_config
  }
  
  boot_disk {
    device_name = "boot"
    auto_delete = true
    initialize_params {
      image = "https://www.googleapis.com/compute/v1/projects/${var.image_project}/global/images/sensor-${var.sensor_version}"
    }
  }
  network_interface {
    subnetwork = data.google_compute_subnetwork.my-subnetwork.self_link
    access_config {
      nat_ip = google_compute_address.static_ip_address.address
    }
    alias_ip_range {
      ip_cidr_range = "/32"
    }
  }

  service_account {
    email  = google_service_account.sensor_service_account.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  depends_on = [time_sleep.wait_disable_org_policies]
}
//24
resource "null_resource" "postdeploy" {
  depends_on = [
    google_compute_instance.sensor_vm
  ]
  /*provisioner "local-exec" {
    command = <<-EOT
      "postdeploy.py --adc_url_hash ${var.adc_url_hash} --session_id ${var.session_id} --sensor_service_account ${google_service_account.sensor_service_account.email} --project_service_account  ${var.dep_service_account} --adc_lb_address ${var.adc_lb_address}"
    EOT
    interpreter = ["python3", "-m"]
  }*/
}

resource "google_scc_source" "custom_source" {
   count        = var.configure_cscc ? 1 : 0
   display_name = "Acalvio ShadowPlex-${random_string.depname.result}"
   organization = var.organization
   description  = "My custom Cloud Security Command Center Finding Source"
 }

resource "google_project_iam_member" "sensor_iam7" {
   count      = var.is_shared_vpc ? 1 : 0
   project    = var.host_project
   role       = "roles/compute.networkUser"
   member     = format("serviceAccount:%s", google_service_account.sensor_service_account.email)
}

######################################################
## VPC Service Controls - Dashboard and Alerts Demo ##
######################################################

module "vpcsc_logging" {
  source                          = "../../modules/vpcsc_logging"
  org_id                          = var.organization
  project_id                      = var.project
  log_bucket_name                 = var.vpcsc_log_bucket
  log_based_metric_name           = var.vpcsc_log_based_metric
  log_router_aggregated_sink_name = var.vpcsc_log_router_aggregated_sink
}

module "vpcsc_dashboard" {
  count                 = var.add_vpcsc_dashboard ? 1 : 0
  source                = "../../modules/vpcsc_dashboard"
  depends_on            = [module.vpcsc_logging]
  project_id            = var.project
  log_based_metric_name = var.vpcsc_log_based_metric
}

module "vpcsc_alerting" {
  count                 = var.add_vpcsc_alerting ? 1 : 0
  source                = "../../modules/vpcsc_alerting"
  depends_on            = [module.vpcsc_logging]
  project_id            = var.project
  email_address         = var.vpcsc_email_address
  log_based_metric_name = var.vpcsc_log_based_metric
}

###############################################
## Security Posture with IaC Validation Demo ##
###############################################

/* pending terraform provider upgrade

resource "google_securityposture_posture" "posture_iac_demo" {
  posture_id  = "posture_iac_demo"
  parent      = "organizations/${organization}"
  location    = "global"
  state       = "ACTIVE"
  description = "security posture demo with iac validation"
  policy_sets {
    policy_set_id = "org_policy_set"
    description   = "set of org policies"
    policies {
      policy_id = "policy_1"
      constraint {
        org_policy_constraint {
          canned_constraint_id = "storage.uniformBucketLevelAccess"
          policy_rules {
            enforce = true
          }
        }
      }
    }
  }
}

resource "google_securityposture_posture_deployment" "posture_iac_deployment_demo" {
  posture_deployment_id = "posture_iac_deployment_demo"
  parent                = "organizations/${organization}"
  location              = "global"
  description           = "deployment of security posture demo with iac"
  target_resource       = "projects/${project}"
  posture_id            = google_securityposture_posture.posture_iac_demo.name
  posture_revision_id   = google_securityposture_posture.posture_iac_demo.revision_id
}
*/
