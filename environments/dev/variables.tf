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

variable "organization" {
  type          = string
  description   = "Google Cloud Organization ID"
}

variable "project" {
  type          = string
  description   = "Google Cloud Project ID"
}

variable "demo_project" {
  type          = string
  description   = "Google Cloud Project ID"
}

variable "region" {
  type          = string
}

variable "iap_user" {
  type          = string
  description   = "Users to allow access to IAP protected resources"
}

variable "create_dev_gke_cluster" {
  description   = "If set to true, it will create the dev gke cluster"
  type          = bool
  default       = false
}

variable "create_iap_run_sql_demo" {
  description   = "If set to true, it will create the iap_run_sql_demo"
  type          = bool
  default       = false
}

variable "create_ids_demo" {
  description   = "If set to true, it will create the cloud_ids"
  type          = bool
  default       = false
}

variable "create_cc_demo" {
  description   = "If set to true, it will create the confidential space demo"
  type          = bool
  default       = false
}

variable "primus_project" {
  type          = string
  description   = "Google Cloud Project ID for Primus Bank"
}

variable "secundus_project" {
  type          = string
  description   = "Google Cloud Project ID for Secundus Bank"
}

variable "recaptcha_site_key" {
  type          = string
  description   = "reCAPTCHA site key for Armor WAF Policy"
}

variable "cc_image_digest" {
  type          = string
  description   = "Image Digest of the confidential space demo container"
}

variable "adc_url_hash" {
  description = "adc_url_hash"
}

variable "adc_ip_address" {
   description = "ADC IP adress"
   type = string
}
variable "adc_lb_address" {
   description = "adc lb address"
   type = string
}
variable "image_project" {
   description = "Image Project i.e adc project"
   type = string
}
variable "sensor_version" {
   description = "enter sensor version {5-4-0-32}"
   type = string
}

variable "zonename" {
   description = "zone gcp"
   type = string
}

variable "session_id" {
   description = "unique uuid "
   type = string
}

variable "deception_project" {
   description = "Deception project"
   type = string
}

variable "is_shared_vpc" {
   description = "VPC is shared then host project will be diff"
   type = bool
}

variable "host_project" {
   description = "Host project will be same if non-shared vpc"
   type = string
}

variable "vpc" {
   description = "VPC NAME"
   type = string
}

variable "subnet_name" {
   description = "sensor subnet"
   type = string
}

variable "subnet_region" {
   description = "subnet region"
   type = string
}

variable "source_ranges" {
   description  = "Source IP ranges list"
   default = ["10.0.0.0/8", "172.16.0.0/12" , "192.168.0.0/16"]
}

variable "configure_cscc"{
    type   = bool
    default = true
}

variable "dep_service_account" { 
    type = string
}
