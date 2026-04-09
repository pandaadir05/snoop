//! Container and Kubernetes target resolution.
//!
//! Translates a Docker container name/ID or a Kubernetes pod name into a host
//! PID that snoop can attach to.  The resolved PID is the *root* process of
//! the container (the container's PID 1 as seen from the host kernel), and
//! snoop attaches with `--follow` so all container children are also traced.
//!
//! # Docker
//!
//! ```text
//! sudo snoop --docker nginx
//! sudo snoop --docker abc123def456
//! ```
//!
//! Uses `docker inspect --format={{.State.Pid}}` to look up the root PID.
//! Falls back to a `/proc/<pid>/cgroup` scan when the Docker CLI is absent
//! (e.g., when only containerd is running).
//!
//! # Kubernetes
//!
//! ```text
//! sudo snoop --pod my-pod
//! sudo snoop --pod my-pod --namespace kube-system
//! ```
//!
//! Queries `kubectl get pod` for the container ID(s), then finds the matching
//! host PID by scanning `/proc/<pid>/cgroup` for the container ID.  This works
//! for Docker, containerd, and CRI-O runtimes without requiring `crictl`.

use std::process::Command;

use anyhow::{bail, Context, Result};

// ── Docker ────────────────────────────────────────────────────────────────────

/// Resolve a Docker container name or ID to the host PID of its root process.
///
/// Requires `docker` to be in `$PATH`.  Falls back to a `/proc` cgroup scan
/// when the CLI is unavailable.
pub fn resolve_docker(name: &str) -> Result<u32> {
    // Primary path: ask Docker directly.
    match docker_inspect_pid(name) {
        Ok(pid) => return Ok(pid),
        Err(e) => {
            log::debug!("docker inspect failed ({e}), falling back to cgroup scan");
        }
    }

    // Fallback: scan /proc for a process whose cgroup path contains the name/ID.
    // This works when the Docker CLI is absent but the container runtime wrote
    // cgroup entries (all modern runtimes do).
    let short = short_id(name);
    find_pid_by_cgroup(short).with_context(|| {
        format!(
            "could not find a running process for Docker container {name:?}.\n\
             Make sure the container is running: docker ps | grep {name}"
        )
    })
}

/// Shell out to `docker inspect` for the container's root PID.
fn docker_inspect_pid(name: &str) -> Result<u32> {
    let out = Command::new("docker")
        .args(["inspect", "--format={{.State.Pid}}", name])
        .output()
        .context("failed to run `docker inspect` — is Docker installed?")?;

    if !out.status.success() {
        bail!(
            "docker inspect: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let pid_str = String::from_utf8_lossy(&out.stdout);
    let pid_str = pid_str.trim();
    let pid: u32 = pid_str
        .parse()
        .with_context(|| format!("docker inspect returned non-numeric PID: {pid_str:?}"))?;

    if pid == 0 {
        bail!("container {name:?} is not running (PID = 0)");
    }

    Ok(pid)
}

// ── Kubernetes ────────────────────────────────────────────────────────────────

/// Resolve a Kubernetes pod name to the host PID of its first container's
/// root process.
///
/// Requires `kubectl` to be in `$PATH` and configured to reach the cluster.
/// Uses a `/proc` cgroup scan to convert the container ID to a host PID,
/// so no `crictl` or runtime-specific CLI is needed.
pub fn resolve_pod(pod: &str, namespace: &str) -> Result<u32> {
    // Ask kubectl for the container ID(s) of the pod.
    let out = Command::new("kubectl")
        .args([
            "get",
            "pod",
            pod,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.containerStatuses[*].containerID}",
        ])
        .output()
        .context("failed to run `kubectl` — is kubectl installed and configured?")?;

    if !out.status.success() {
        bail!(
            "kubectl get pod: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let ids_str = String::from_utf8_lossy(&out.stdout);
    let ids_str = ids_str.trim();

    if ids_str.is_empty() {
        bail!(
            "pod {pod:?} in namespace {namespace:?} has no running containers.\n\
             Check pod status: kubectl get pod {pod} -n {namespace}"
        );
    }

    // Use the first container ID (pods may have multiple containers; --container
    // flag could refine this in the future).
    let first = ids_str.split_whitespace().next().unwrap_or(ids_str);
    let container_id = strip_runtime_prefix(first);
    let short = short_id(container_id);

    log::debug!("pod {pod}: resolved container ID {container_id:.12}, scanning /proc");

    find_pid_by_cgroup(short).with_context(|| {
        format!(
            "could not find a running process for pod {pod:?} \
             (container {container_id:.12}).\n\
             Is the pod running?  kubectl get pod {pod} -n {namespace}"
        )
    })
}

// ── shared helpers ────────────────────────────────────────────────────────────

/// Strip `docker://`, `containerd://`, `cri-o://`, etc. from a container ID.
fn strip_runtime_prefix(id: &str) -> &str {
    if let Some(pos) = id.find("://") {
        &id[pos + 3..]
    } else {
        id
    }
}

/// Take up to the first 12 characters (the canonical short-form container ID).
/// Short IDs are unambiguous in practice and match how runtimes write cgroup paths.
fn short_id(id: &str) -> &str {
    let end = id.len().min(12);
    // Ensure we don't split a multi-byte UTF-8 codepoint (container IDs are
    // always hex strings, so this is safe — every byte is ASCII).
    &id[..end]
}

/// Scan `/proc` for the lowest-numbered PID whose cgroup file contains `id`.
///
/// Returns the root process (lowest PID = container PID 1 on the host).
fn find_pid_by_cgroup(id: &str) -> Result<u32> {
    if id.is_empty() {
        bail!("empty container ID");
    }

    let mut best: Option<u32> = None;

    let entries = std::fs::read_dir("/proc")
        .context("could not read /proc — is this Linux?")?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only consider numeric directories (PIDs).
        let pid: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let cgroup_path = format!("/proc/{pid}/cgroup");
        let contents = match std::fs::read_to_string(&cgroup_path) {
            Ok(c) => c,
            Err(_) => continue, // process may have exited
        };

        if contents.contains(id) {
            best = Some(match best {
                None => pid,
                Some(prev) if pid < prev => pid,
                Some(prev) => prev,
            });
        }
    }

    best.ok_or_else(|| {
        anyhow::anyhow!(
            "no process found with container ID {id:?} in /proc cgroup entries"
        )
    })
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_docker_prefix() {
        assert_eq!(
            strip_runtime_prefix("docker://abc123def456"),
            "abc123def456"
        );
    }

    #[test]
    fn strip_containerd_prefix() {
        assert_eq!(
            strip_runtime_prefix("containerd://abc123def456789"),
            "abc123def456789"
        );
    }

    #[test]
    fn strip_crio_prefix() {
        assert_eq!(strip_runtime_prefix("cri-o://deadbeef1234"), "deadbeef1234");
    }

    #[test]
    fn strip_no_prefix() {
        assert_eq!(strip_runtime_prefix("plainid123"), "plainid123");
    }

    #[test]
    fn short_id_truncates() {
        assert_eq!(short_id("abcdef123456789"), "abcdef123456");
        assert_eq!(short_id("short"), "short");
    }

    #[test]
    fn find_pid_by_cgroup_empty_id_errors() {
        assert!(find_pid_by_cgroup("").is_err());
    }
}
