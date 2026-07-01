#!/usr/bin/env bash
set -euo pipefail

policy_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bot_code_dir="${WEBEX_BOT_CODE_DIR:-$(cd "$policy_root/../.." && pwd)}"
environment="production"
source_root=""
output=""
output_explicit=0
skip_bot_check=0
stage_runner_activation=0
node_bin="${NODE_BIN:-node}"
python_bin="${PYTHON_BIN:-python3}"
bot_bin="${BOT_BIN:-$bot_code_dir/target/debug/webex-generic-account-bot}"
max_rendered_config_bytes="${MAX_RENDERED_CONFIG_BYTES:-4194304}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      environment="${2:?--env requires a value}"
      shift 2
      ;;
    --source-root)
      source_root="${2:?--source-root requires a value}"
      shift 2
      ;;
    --out)
      output="${2:?--out requires a value}"
      output_explicit=1
      shift 2
      ;;
    --skip-bot-check)
      skip_bot_check=1
      shift
      ;;
    --stage-runner-activation)
      stage_runner_activation=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! "$environment" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "environment must be a simple directory name: $environment" >&2
  exit 2
fi

if [[ -z "$source_root" ]]; then
  echo "--source-root is required" >&2
  exit 2
fi
if [[ "$source_root" != /* ]]; then
  echo "--source-root must be an absolute path: $source_root" >&2
  exit 2
fi
if [[ ! -d "$source_root" ]]; then
  echo "source root must be a directory: $source_root" >&2
  exit 2
fi

if [[ "$skip_bot_check" == 1 && "$output_explicit" == 1 ]]; then
  echo "--skip-bot-check cannot be used with an explicit --out path" >&2
  exit 2
fi
if [[ "$stage_runner_activation" == 1 && "$skip_bot_check" == 1 ]]; then
  echo "--stage-runner-activation cannot be combined with --skip-bot-check" >&2
  exit 2
fi
if [[ "$stage_runner_activation" == 1 && "$output_explicit" != 1 ]]; then
  echo "--stage-runner-activation requires an explicit --out path" >&2
  exit 2
fi

if [[ -z "$output" ]]; then
  output="$bot_code_dir/build/$environment.toml"
elif [[ "$output" != /* ]]; then
  output="$bot_code_dir/$output"
fi
install_flags=()
if [[ "$output_explicit" == 0 ]]; then
  install_flags+=(--allow-unsafe-parents)
fi

output_dir="$(dirname "$output")"
output_base="$(basename "$output")"
if [[ -d "$output" ]]; then
  echo "output path must be a file, not a directory: $output" >&2
  exit 2
fi
new_output_dirs=()
scan_dir="$output_dir"
while [[ ! -d "$scan_dir" ]]; do
  new_output_dirs+=("$scan_dir")
  parent_dir="$(dirname "$scan_dir")"
  if [[ "$parent_dir" == "$scan_dir" ]]; then
    break
  fi
  scan_dir="$parent_dir"
done
"$python_bin" "$policy_root/install-rendered-config.py" "${install_flags[@]}" --parent-check "$scan_dir"
(umask 022 && mkdir -p "$output_dir")
for ((index=${#new_output_dirs[@]} - 1; index >= 0; index -= 1)); do
  chmod 755 "${new_output_dirs[$index]}"
done
"$python_bin" "$policy_root/install-rendered-config.py" "${install_flags[@]}" --directory-check "$output_dir"
temp_output="$(mktemp "$output_dir/.${output_base}.tmp.XXXXXX")"
cleanup_temp_output() {
  if [[ -n "${temp_output:-}" && -f "$temp_output" ]]; then
    rm -f "$temp_output"
  fi
}
trap cleanup_temp_output EXIT

install_rendered_config() {
  local source="$1"
  local target="$2"
  "$python_bin" "$policy_root/install-rendered-config.py" "${install_flags[@]}" "$source" "$target"
  temp_output=""
}

"$node_bin" "$policy_root/render-config.mjs" --env "$environment" --source-root "$source_root" --max-bytes "$max_rendered_config_bytes" --stdout > "$temp_output"

static_check_args=()
if [[ "$stage_runner_activation" == 1 ]]; then
  static_check_args+=(--require-ephemeral-linux-user)
fi
"$python_bin" "$policy_root/static-config-check.py" "${static_check_args[@]}" "$temp_output"

if [[ "$stage_runner_activation" == 1 ]]; then
  install_rendered_config "$temp_output" "$output"
  trap - EXIT
  echo "rendered_config=$output"
  echo "bot_check_deferred=true reason=runner_activation"
  exit 0
fi

if [[ "$skip_bot_check" == 1 ]]; then
  install_rendered_config "$temp_output" "$output"
  trap - EXIT
  echo "rendered_config=$output"
  echo "bot_check_skipped=true reason=explicit"
  exit 0
fi

if [[ ! -x "$bot_bin" ]]; then
  echo "bot_check_failed=true reason=missing_bot_binary path=$bot_bin" >&2
  exit 1
fi

"$bot_bin" --config "$temp_output" --check-config

install_rendered_config "$temp_output" "$output"
trap - EXIT
echo "rendered_config=$output"
