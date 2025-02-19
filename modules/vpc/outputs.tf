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

output "id" {
  value = "${google_compute_network.vpc.id}"
}

output "name" {
  value = "${google_compute_network.vpc.name}"
}

output "subnet" {
  value = "${google_compute_subnetwork.subnet.id}"
}

output "subnet_ip" {
  value = "10.${var.env == "dev" ? 10 : 20}.0.0/24"
}
