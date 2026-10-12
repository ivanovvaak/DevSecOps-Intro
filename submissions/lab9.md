# Lab 9 — Runtime Detection and Policy as Code

Falco `0.43.1` (libs 0.23.2), Conftest with OPA 1.21.0.

**Where this ran.** Docker Desktop's VM does not expose a usable host kernel, exactly as the setup section warns, so Falco runs inside a Lima VM of type `vz` on kernel `6.8.0-138-generic`. Conftest needs no kernel and ran on the host. Falco's startup log carries the documented tracepoint warnings:

```
libbpf: prog 'openat2_e': failed to create tracepoint 'syscalls/sys_enter_openat2' perf event: No such file or directory
libpman: failure while attaching TOCTOU mitigation program for 'openat2' system call.
         Detection will continue to work, but TOCTOU mitigation may not properly work
```

The container stays `Up`, and detection works — but the missing tracepoints turn out to matter for the bonus, below.

## Task 1

### The two built-in rules

```bash
$ docker exec -t lab9-target sh -lc 'echo hello-from-shell'
$ docker exec lab9-target sh -c 'cat /etc/shadow'
$ docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
      1 "rule":"Read sensitive file untrusted"
      1 "rule":"Terminal shell in container"
```

**1. `Terminal shell in container` (Notice), triggered by the first command.**

```
A shell was spawned in a container with an attached terminal | evt_type=execve
user=root user_uid=0 process=sh proc_exepath=/bin/busybox parent=containerd-shim
command=sh -lc echo hello-from-shell terminal=34816
exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=66247b4e9e47
container_name=lab9-target container_image_repository=alpine container_image_tag=3.20
```

What fired it is `terminal=34816` — a non-zero tty. The `-t` flag is the whole point: it attaches a pseudo-terminal, and the rule keys on that rather than on the command looking shell-like. A plain `docker exec lab9-target sh -lc '...'` runs the same shell and produces no alert. The signal is not "a shell ran" but "a human is typing into this container", which in a production image nobody should be.

**2. `Read sensitive file untrusted` (Warning), triggered by the second.**

```
Sensitive file opened for reading by non-trusted program | file=/etc/shadow
gparent=systemd evt_type=openat user=root user_uid=0 process=cat
proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow
container_id=66247b4e9e47 container_name=lab9-target
```

Here it is the file, not the terminal: `/etc/shadow` is on Falco's sensitive-files list and `cat` is not on its trusted-reader list. Note this one fired from a *plain* `docker exec` with `terminal=0` — the two rules watch different things, which is why the lab asks for both commands.

### My rule, and the alert proving it fired

`labs/lab9/falco/rules/custom-rules.yaml`:

```yaml
- rule: Write to tmp in container
  desc: >
    A file under /tmp was opened for writing from inside a container. /tmp is the
    usual landing zone for a dropped payload: it is world-writable, it survives
    just long enough to execute, and it is excluded from most image-integrity
    checks. On a container with a read-only root filesystem (Lab 7) this should
    not happen at all outside the volumes we mounted on purpose.
  condition: >
    open_write
    and container.id != host
    and fd.name startswith /tmp/
  output: >
    File written under /tmp inside a container
    (file=%fd.name container=%container.name image=%container.image.repository:%container.image.tag
     user=%user.name uid=%user.uid process=%proc.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

`open_write` is the shipped macro, read out of the image rather than guessed:

```bash
$ docker exec falco grep -A2 'macro: open_write' /etc/falco/falco_rules.yaml
- macro: open_write
  condition: (evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0)
```

Firing it:

```bash
$ docker kill --signal=SIGHUP falco && sleep 5
$ docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
$ docker logs falco 2>&1 | grep -c '"rule":"Write to tmp in container"'
1
```

```json
{
  "rule": "Write to tmp in container",
  "priority": "Warning",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-10-12T17:07:32.195697438Z",
  "output": "Warning File written under /tmp inside a container (file=/tmp/my-write.txt container=lab9-target image=alpine:3.20 user=root uid=0 process=sh cmdline=sh -lc echo test > /tmp/my-write.txt) container_id=66247b4e9e47 ...",
  "output_fields": {
    "container.id": "66247b4e9e47",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791824852195697438,
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "proc.name": "sh",
    "user.name": "root",
    "user.uid": 0
  }
}
```

### One JSON field that matters in an incident and is not in the message

**`evt.time.iso8601`, the raw nanosecond value `1791824852195697438`.**

The human-readable line carries a timestamp formatted to the second. During an incident the question is almost never "what happened" but "in what order" — did the write to `/tmp` precede or follow the outbound connection, did the shell spawn before or after the file read. Container activity happens in bursts where a dozen syscalls share the same displayed second, and a sorted log of formatted timestamps silently reorders them. The nanosecond integer is what lets you merge Falco's stream with a web-server log or an audit log and get a sequence you can defend.

`container.id` is a close second for the same reason: the message names `container=lab9-target`, and container *names* are reused across restarts and deployments, while `66247b4e9e47` identifies the exact instance that did this.

### The false positive this rule will generate

The rule fires on **every** `/tmp` write in **every** container, and the workload it will flag first is any JVM or Python application: the JDK writes `/tmp/hsperfdata_<user>` on startup and on every `jcmd`, and `pip`, `apt` and most build tooling stage downloads under `/tmp`. A CI runner image would produce thousands of alerts an hour and the rule would be muted within a day — which is the real failure mode, since a muted rule detects nothing.

Keeping the detection while dropping the noise means narrowing on what is actually suspicious, not on the directory. Three changes, in order of how much they buy: exclude known-benign paths and writers with a macro (`not (proc.name in (java, pip, apt-get) and fd.name startswith /tmp/hsperfdata)`); restrict the rule to images that should never write at all — the Lab 7 deployment runs with `readOnlyRootFilesystem: true`, so for *that* container any write is by definition drift; and raise the bar from "written" to "written and then executed", since a payload that is dropped but never run is a different severity from one that is. The general principle is that the exclusion list belongs to the workload, not to the rule: the same `/tmp` write is routine in a build container and alarming in a hardened production pod.

## Task 2

### Counts for all three files

| File | Tests | Passed | Warnings | Failures |
|---|---:|---:|---:|---:|
| `k8s/juice-hardened.yaml` | 30 | 30 | 0 | 0 |
| `k8s/juice-unhardened.yaml` | 30 | 20 | 2 | 8 |
| `compose/juice-compose.yml` | 15 | 15 | 0 | 0 |

### Two failures mapped to their Rego rules

```
FAIL - container "juice" uses disallowed :latest tag
FAIL - container "juice" must set runAsNonRoot: true
```

Both come from `labs/lab9/policies/k8s-security.rego`, package `k8s.security`:

```rego
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  endswith(c.image, ":latest")
  msg := sprintf("container %q uses disallowed :latest tag", [c.name])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not c.securityContext.runAsNonRoot
  msg := sprintf("container %q must set runAsNonRoot: true", [c.name])
}
```

Each walks `input.spec.template.spec.containers[_]` and emits one message per offending container. Note the second uses `not c.securityContext.runAsNonRoot`, which catches both "set to false" and "absent" — the unhardened manifest has no `securityContext` at all, and `not` over an undefined path succeeds.

### Why Compose needs its own rule, and what its passing means

The same requirement needs two rules because the *document shape* is different, not because the requirement is. "Do not run as root" is `spec.template.spec.containers[_].securityContext.runAsNonRoot` in a Deployment and `services.<name>.user` in a Compose file; Rego matches on structure, so a policy written for one is simply blind to the other — it finds no `input.kind == "Deployment"`, every rule body fails, and the file passes vacuously.

Which is exactly why the Compose file passing all 15 checks is worth stating out loud: **it passed its own policy, not the Kubernetes one.** A policy set that only ever reports failures teaches you nothing about whether it is wired up, and a file that passes because nothing applied to it looks identical, in CI, to a file that passes because it is correct. The 15 checks here are real assertions from `compose-security.rego` against this file; the proof that the Kubernetes policy is also live is the 8 failures next door.

### My policy

`labs/lab9/policies/extra/hardening.rego` — same package so Conftest evaluates it alongside the shipped rules:

```rego
package k8s.security

# DENY: the image must be pinned by digest, not by a tag.
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q must pin its image by digest, not by tag (got %q)", [c.name, c.image])
}

# WARN: a Service should not be published as NodePort or LoadBalancer.
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
```

The deny rule exists because the shipped policy only rejects `:latest`, which leaves `:v20.0.0` looking responsible — and Lab 8 showed a signed tag being overwritten with a completely different image in a registry while the name stayed the same. The warn rule exists because every container-level control is irrelevant if the workload is published straight onto the node's network; it is the Lab 1 `127.0.0.1` lesson in Kubernetes form, and a warning rather than a denial because sometimes you do mean to expose it and the reviewer should have to say so.

The manifest written to violate them, `labs/lab9/manifests/k8s/violates-my-policy.yaml`, deliberately satisfies every shipped rule — non-root, no privilege escalation, read-only root filesystem, capabilities dropped, probes, limits, no `:latest` — so the only things wrong with it are the two controls this lab adds.

**Both runs:**

```bash
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
36 tests, 36 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test labs/lab9/manifests/k8s/violates-my-policy.yaml --policy labs/lab9/policies --all-namespaces
WARN - service "juice-tagged" is exposed as NodePort; prefer ClusterIP behind an Ingress
FAIL - container "juice" must pin its image by digest, not by tag (got "bkimminich/juice-shop:v20.0.0")
36 tests, 34 passed, 1 warning, 1 failure, 0 exceptions
```

The test count went from 30 to 36 on the hardened file, which is the check that the new rules are actually being evaluated rather than silently skipped.

### CI or runtime, if I could only keep one

For **this** control — image pinned by digest — I would keep the **Conftest rule in CI**, without much hesitation. The requirement is a property of the manifest, fully decidable before anything runs, and the cost of enforcement is a failed pipeline rather than an incident. Falco cannot even express it well: at runtime the image is already pulled and running, and what Falco sees is a process, not the provenance of the bytes it came from.

What the runtime half still buys is everything the manifest does not say. CI checks the artifact you *intended* to deploy; Falco watches what the thing actually *does* — including the cases where the manifest was fine and the image was not, where someone applied a manifest that never went through CI, or where the pinned-by-digest image turned out to contain a payload nobody scanned for. My `/tmp` rule is the example: no policy file can state "this container will never write a file it did not ship with", because that is a statement about behaviour, and behaviour only exists at runtime. The honest division is that Conftest enforces decisions and Falco detects surprises, and a programme with only one of them is either blind to drift or blind until it is too late.

## Bonus

### The rule

```yaml
- list: mining_pool_ports
  items: [3333, 4444, 5555, 7777, 14444]

- list: suspect_network_binaries
  items: [xmrig, minerd, cpuminer, ccminer, cgminer, nheqminer, xmr-stak, nc, ncat, netcat, curl, wget]

- list: known_pool_endpoints
  items: ["127.0.0.1:3333"]

- macro: pool_port_contacted
  condition: (fd.sport in (mining_pool_ports) or evt.arg.addr in (known_pool_endpoints))

- rule: Cryptomining connection from container
  desc: >
    A process inside a container attempted an outbound connection to a port
    commonly used by mining pools, and the process is one that has no business
    opening arbitrary sockets from this image. Either signal alone is noisy:
    port 4444 is used by plenty of legitimate software, and curl exists in half
    the images on earth. Together they are the shape of the Tesla incident --
    an exposed workload quietly joined a pool and nobody looked at egress.
  condition: >
    evt.type = connect
    and evt.dir = <
    and container.id != host
    and proc.name in (suspect_network_binaries)
    and pool_port_contacted
  output: >
    Possible cryptomining connection from a container
    (container=%container.name image=%container.image.repository:%container.image.tag
     process=%proc.name cmdline=%proc.cmdline user=%user.name
     destination=%evt.arg.addr result=%evt.res)
  priority: CRITICAL
  tags: [container, mitre_command_and_control, T1496, cryptomining]
```

### The alert

```bash
$ docker kill --signal=SIGHUP falco && sleep 5
$ docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333' || true
$ docker logs falco 2>&1 | grep -c '"rule":"Cryptomining connection from container"'
```

```json
{
  "rule": "Cryptomining connection from container",
  "priority": "Critical",
  "tags": ["T1496", "container", "cryptomining", "mitre_command_and_control"],
  "time": "2026-10-12T17:16:13.384523893Z",
  "output": "Critical Possible cryptomining connection from a container (container=lab9-target image=alpine:3.20 process=nc cmdline=nc -w 2 127.0.0.1 3333 user=root destination=127.0.0.1:3333 result=ECONNREFUSED)",
  "output_fields": {
    "container.name": "lab9-target",
    "evt.arg.addr": "127.0.0.1:3333",
    "evt.res": "ECONNREFUSED",
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.name": "nc",
    "user.name": "root"
  }
}
```

**Two things cost me real time here and belong in the write-up.**

The lab's hint says to use `fd.sport` and that a refused connection still produces the event. Both halves are true; together they are not. On this kernel a refused `connect()` produces the exit event, but the socket never acquires a peer, so `fd.name` is `0.0.0.0:0` and `fd.sport`, `fd.sip` and `fd.rport` are all `<NA>`. The destination survives only as the syscall argument, `evt.arg.addr`. I found this by writing a throwaway DEBUG rule printing every field rather than guessing:

```
DEBUG (proc=nc sport=<NA> sip=<NA> fdname=0.0.0.0:0 res=ECONNREFUSED addr=127.0.0.1:3333)
```

And `evt.arg.addr` is a *typed* field, not a string: `contains`, `endswith` and `regex` are all rejected at rule-compile time, so matching a port suffix is impossible and only `=` and `in` work. My first attempt used `endswith_any`, which does not exist at all, and Falco refused the entire file — including the working `/tmp` rule — with `LOAD_ERR_COMPILE_CONDITION`. Checking `docker logs falco` after every SIGHUP, as the pitfalls section says, is the only reason I noticed.

The result is a macro with two branches: `fd.sport` for established connections (the production case, where a miner holds a long-lived session to a pool) and an exact-match endpoint list for everything else. In production that list is an IOC feed; here it carries the lab's own test destination.

### Why a refused connection is enough, and where Falco sits

A refused connection is enough because Falco is not watching the network — it is watching the **kernel's syscall boundary**. The event is `connect()` returning `ECONNREFUSED`, and that syscall was made, and recorded, before any packet got an answer. Nothing has to succeed for Falco to see the intent; the process asked the kernel to reach `127.0.0.1:3333`, and the asking is the evidence.

That places Falco somewhere a firewall and a packet sniffer cannot reach. A network monitor sees traffic that left the host, so a connection refused at the first hop may produce nothing worth alerting on, and anything encrypted is opaque to it. Falco sees *which process, in which container, as which user, with which command line* made the attempt — attribution that is simply absent from a packet capture. It is also why egress filtering and runtime detection are complements rather than alternatives: the firewall stops the connection, and Falco tells you who tried.

### An attacker reads the rule and changes port

**Free to evade: the port.** `mining_pool_ports` is a list of five integers, and every major pool offers connections on 443 or 80 precisely because those traverse corporate networks. Changing a config line costs the attacker nothing and defeats that half of the condition completely. The endpoint IOC list is barely better — a new pool address, or a self-hosted proxy, and the list is stale.

**Expensive to evade: the behaviour.** The miner must run a process that burns CPU continuously, maintains a long-lived outbound connection, and reconnects when it drops. Renaming the binary from `xmrig` to `nginx-worker` is free, but *not spinning the CPU* is not, because CPU is the product being stolen. That asymmetry is where the durable detection lives.

So I would add two things and accept that the port rule is a cheap tripwire rather than a control. First, a behavioural rule that does not mention ports at all: a container process holding an outbound connection for more than N minutes while the container's CPU sits pinned, which costs the attacker actual revenue to evade. Second, invert the logic — rather than enumerating bad destinations, alert on any egress from a workload that has no business making outbound connections at all. The Lab 7 NetworkPolicy already encodes that intent (DNS only), so the detection rule and the prevention control can be generated from the same statement, and an attacker who evades the detection still has to get past the policy.
