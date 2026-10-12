# Two controls the shipped policy does not make.
# Same package as k8s-security.rego so conftest evaluates them together.
package k8s.security

# DENY: the image must be pinned by digest, not by a tag.
#
# The shipped policy only rejects ":latest". That leaves ":v20.0.0" looking
# safe, and a tag is a mutable pointer: Lab 8 demonstrated overwriting a signed
# tag with a different image in a registry. A digest is the content.
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin its image by digest, not by tag (got %q)", [c.name, c.image])
}

# WARN: a Service should not be published as NodePort or LoadBalancer.
#
# Every container-level control in the shipped policy is irrelevant if the
# workload is published straight onto the node's network. This is the Lab 1
# lesson -- binding to 0.0.0.0 instead of 127.0.0.1 -- expressed for Kubernetes.
# A warning rather than a denial: sometimes you really do mean to expose it,
# and then the reviewer should say so out loud.
warn contains msg if {
  input.kind == "Service"
  input.spec.type == "NodePort"
  msg := sprintf("service %q is exposed as NodePort; prefer ClusterIP behind an Ingress", [input.metadata.name])
}

warn contains msg if {
  input.kind == "Service"
  input.spec.type == "LoadBalancer"
  msg := sprintf("service %q is exposed as LoadBalancer; confirm this is intentional", [input.metadata.name])
}
