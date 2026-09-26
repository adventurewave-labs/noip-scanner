#!/usr/bin/env bash
# Mint a short-lived, read-only kubeconfig for the `noip` ServiceAccount (deploy/rbac.yaml).
# Use this for client scans so NOIP never runs with your admin credentials.
#   kubectl apply -f deploy/rbac.yaml
#   scripts/sa-kubeconfig.sh noip.kubeconfig [duration]    # default 1h
#   noip scan --kubeconfig noip.kubeconfig -o md --out report.md
set -euo pipefail
out=${1:-noip.kubeconfig}
duration=${2:-1h}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
ca=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
token=$(kubectl -n noip-system create token noip --duration="$duration")

kubectl config --kubeconfig="$out" set-cluster target --server="$server" >/dev/null
if [ -n "$ca" ]; then
  echo "$ca" | base64 -d > "$tmp/ca.crt"
  kubectl config --kubeconfig="$out" set-cluster target --certificate-authority="$tmp/ca.crt" --embed-certs=true >/dev/null
fi
kubectl config --kubeconfig="$out" set-credentials noip --token="$token" >/dev/null
kubectl config --kubeconfig="$out" set-context noip-ro --cluster=target --user=noip >/dev/null
kubectl config --kubeconfig="$out" use-context noip-ro >/dev/null
chmod 600 "$out"

if [ "$(kubectl --kubeconfig="$out" auth can-i get secrets -A)" != "no" ]; then
  echo "refusing: the noip ServiceAccount can read secrets — check deploy/rbac.yaml and other bindings" >&2
  exit 1
fi
echo "wrote $out (read-only, expires in $duration)"
