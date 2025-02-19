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
  type        = string
  description = "Google Cloud Organization ID"
}

variable "project" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "demo_project" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "test_project" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "region" {
  type        = string
}

variable "slack_secops_channel" {
  type        = string
}

variable "slack_approver_channel" {
  type        = string
}

variable "cloud_identity_domain" {
  type        = string
}

variable "website_username" {
  type        = string
}

variable "slack_devops_channel" {
  type      = string
}

variable "atlassian_email" {
  type      = string
}

variable "atlassian_domain" {
  type      = string
}

variable "jira_project_key" {
  type      = string
}

variable "dlp_wrapped_key" {
  type      = string
}

variable "create_prod_gke_cluster" {
  description   = "If set to true, it will create the prod gke cluster"
  type          = bool
  default       = false
}

variable "slack_admin" {
  type        = string
}

variable "slack_ctf_admin_channel" {
  type        = string
}

variable "ctf_project" {
  type        = string
}

variable "challenges_collection" {
  type        = string
}

variable "games_collection" {
  type        = string
}

variable "last_challenge" {
  type        = string
}

variable "secure_tag" {
  default = null
  type = object(
    {
      key             = string
      default_value   = string
    }
  )
}

variable "customer_id" {
  type        = string
  description = "Google Identity Customer ID"
}
