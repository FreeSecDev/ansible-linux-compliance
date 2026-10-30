#!/usr/bin/env bash
set -euo pipefail

readonly SHA='^[0-9a-f]{40}$'
readonly USAGE='usage: plan-lifecycle.sh <event> <base sha> <head sha or empty> <docker matrix> <libvirt matrix>'

event="${1:-}"
base="${2:-}"
head="${3:-}"
docker="${4:-}"
libvirt="${5:-}"

refuse() {
  printf 'plan-lifecycle: %s; plan the full matrix\n' "$1" >&2
  exit 1
}

case "${event}" in
  pull_request)
    if [[ -z "${head}" ]]; then
      head="$(git rev-parse HEAD)"
    fi
    ;;
  merge_group) ;;
  *) refuse "the ${event:-unnamed} event always runs the full matrix" ;;
esac
[[ "${base}" =~ ${SHA} ]] || refuse "the base revision is not a commit SHA"
[[ "${head}" =~ ${SHA} ]] || refuse "the head revision is not a commit SHA"
[[ "$(git rev-parse HEAD)" == "${head}" ]] || refuse "the checkout is not the head revision"
[[ -f "${docker}" && -f "${libvirt}" ]] || refuse "${USAGE}"
git cat-file -e "${base}^{commit}" 2>/dev/null || refuse "the base revision is not in the clone"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
git diff --no-renames --name-only -z "${base}" "${head}" -- > "${work}/changed" || refuse "git diff failed"
mkdir "${work}/base"
git archive --format=tar "${base}" | tar -xf - -C "${work}/base" || refuse "the base revision cannot be exported"

env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL make -C "${work}/base" --no-print-directory -s molecule-affected \
  MOLECULE_AFFECTED_HEAD="${PWD}" \
  MOLECULE_AFFECTED_CHANGED="${work}/changed" \
  MOLECULE_AFFECTED_DOCKER="$(realpath "${docker}")" \
  MOLECULE_AFFECTED_LIBVIRT="$(realpath "${libvirt}")" \
  || refuse "the base revision's planner failed"
