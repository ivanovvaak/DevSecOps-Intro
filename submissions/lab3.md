# Lab 3 — Secure Git: Signed Commits, Secret Scanning, and History Hygiene

## Task 1

### Signing configuration

```bash
$ git config --global gpg.format
ssh
$ git config --global user.signingkey
/Users/katyaivanova/.ssh/id_ed25519.pub
$ git config --global commit.gpgsign
true
```

`tag.gpgsign` is also `true`, and `gpg.ssh.allowedSignersFile` points at `~/.config/git/allowed_signers`, whose single line is

```
ekate0646@gmail.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEtAK9m... ekate0646@gmail.com
```

Without that file Git signs happily and then cannot verify its own work: `git log --show-signature` prints `No principal matched` instead of a good signature.

### Proof it works

```bash
$ git log --show-signature -1
commit e7aa3c3e1f2d122db76b895f4417f08d84828221
Good "git" signature for ekate0646@gmail.com with ED25519 key SHA256:BzBwmOVJ2rjldL1oS/Pb2fqfuvf18V/77+g32bD4qGU
Author: Ekaterina Ivanova <ekate0646@gmail.com>
Date:   Sun Sep 13 19:39:14 2026 +0300

    test: first signed commit
```

Commit on GitHub with the **Verified** badge:
https://github.com/ivanovvaak/DevSecOps-Intro/commit/e7aa3c3e1f2d122db76b895f4417f08d84828221

Two registration details cost me time and are worth writing down. The key was already on the account, but only as an **Authentication Key** — `gh ssh-key list` showed exactly one row ending in `authentication`, and commits stayed Unverified. The same key bytes have to be added a second time with type `signing`; after that the list shows two rows for one key. Separately, the private key is passphrase-protected, so signing failed with `Load key ... incorrect passphrase supplied` until the key was loaded into the agent with `ssh-add --apple-use-keychain`.

### What a forged author line buys an attacker

`user.name` and `user.email` are plain strings that anyone can set to anything; nothing in Git checks them. In this repository that means an attacker who can push — a stolen token, a compromised CI credential, a malicious contributor — can land a commit that reads `Author: Ekaterina Ivanova <ekate0646@gmail.com>` and looks exactly like my work in `git log` and in the GitHub UI. If that commit weakens the smoke-test workflow from Lab 1 or edits the gitleaks config below, the reviewer's first instinct is to trust it, because the name on it is a name they trust. That is the **repudiation** risk my Lab 2 model flagged, and it cuts both ways: I could also disown a commit I really did make, since nobody can prove authorship from the author line alone.

The badge changes what the author line *is*. A Verified commit carries a signature over the commit object made with a private key that only I hold, and GitHub checks it against the signing key registered on my account. An attacker who can push can still push, but they cannot produce that signature without the key, so their commit shows up Unverified next to a wall of Verified ones — the anomaly becomes visible instead of invisible. It does not stop the push; it removes the attacker's ability to borrow my identity while doing it, and it removes my ability to deny a commit that carries my signature.

## Task 2

### `.pre-commit-config.yaml`

```yaml
# Local guardrails: nothing leaves this laptop with a secret in it.
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ["--maxkb=1024"]
```

Both `rev:` values are real tags: `v8.30.1` is the current gitleaks 8.x release, `v6.0.0` the current pre-commit-hooks release.

### The blocked commit

```bash
$ git log --oneline -1
e7aa3c3 test: first signed commit

$ printf 'GH_PAT=ghp_16C7e42F292c6912E7710c838347Ae178B4a\n' > submissions/leak-attempt.txt
$ git add submissions/leak-attempt.txt
$ git commit -m "test: should be blocked"
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
- exit code: 1

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

Finding:     GH_PAT=REDACTED
Secret:      REDACTED
RuleID:      github-pat
Entropy:     4.143943
File:        submissions/leak-attempt.txt
Line:        1
Fingerprint: submissions/leak-attempt.txt:github-pat:1

7:41PM INF 0 commits scanned.
7:41PM INF scanned ~48 bytes (48 bytes) in 24.1ms
7:41PM WRN leaks found: 1

detect private key.......................................................Passed
check for added large files..............................................Passed

$ git log --oneline -1
e7aa3c3 test: first signed commit
```

The rule named is `github-pat`, and `git log --oneline -1` still shows the *previous* commit — the blocked one was never created. Cleaned up with `git restore --staged submissions/leak-attempt.txt && rm submissions/leak-attempt.txt`.

Worth recording from the first `pre-commit run --all-files`: gitleaks passed on the whole repository, but `detect-private-key` failed on a file that ships with the course itself —

```
Private key found: labs/lab6/vulnerable-iac/ansible/configure.yml
```

which is a deliberate PEM private-key block in the Lab 6 vulnerable-IaC sample. It is a true positive against a file that is *supposed* to contain a fake key, which is exactly the situation the next question is about.

### Allowlist vs path exclusion for `AKIA...` documentation examples

**A `[allowlist]` entry in `.gitleaks.toml`** targets the value, not the location: you add the specific string (or a tight regex, or the finding's fingerprint) and gitleaks stops reporting *that* thing anywhere in the repository. That is the right shape when the example is a known constant — a teammate documenting `AKIAIOSFODNN7EXAMPLE` is allowlisting a string AWS itself publishes as a non-credential. It stops being safe the moment the entry is written loosely: an allowlist regex like `AKIA[A-Z0-9]{16}` does not match "the documentation example", it matches *every AWS access key ID*, including the real one someone pastes next month. The narrower the match, the longer it stays safe; a fingerprint-based entry is safest because it also pins the file and line.

**A path exclusion for `docs/`** targets the location, not the value: everything under that directory stops being scanned. It is cheaper to write and it survives the examples changing, which makes it tempting for a docs folder full of samples. It stops being safe as soon as `docs/` stops being only documentation — someone adds `docs/runbook.md` with a real token for the on-call procedure, or a generated `docs/` build pulls in a config file, and the scanner is silent by construction because nobody re-reads an exclusion rule written a year earlier. The failure mode is the dangerous one: an allowlist that is too wide still scans and mis-classifies, while a path exclusion does not look at all.

My preference for this repository is the allowlist with a fingerprint, and no path exclusions, because the blind spot is the thing you never notice you have.

### Which I then had to do for real

Committing this very report tripped my own hooks — three findings, all instructive:

| Hook | Finding | Verdict |
|---|---|---|
| `gitleaks` / `github-pat` | line 75, the `printf 'GH_PAT=ghp_16C7...'` command quoted as evidence | true positive on a fake value |
| `gitleaks` / `generic-api-key` | line 29, the `SHA256:BzBwm...` key **fingerprint** printed by `git log --show-signature` | false positive — a fingerprint is a public identifier, but it has the entropy of a secret |
| `detect-private-key` | the PEM armour line I had quoted verbatim when describing the Lab 6 sample | true positive on a string, not on a key |

So I wrote `.gitleaks.toml` the way I argued for above: `useDefault = true` plus two allowlists, each scoped by `paths` to `submissions/lab3.md` *and* by `regexes` to the exact literal value. No `ghp_[A-Za-z0-9]{36}` pattern, and no path exclusion for `submissions/` — either would have silenced a real token in a future lab report.

My first version of that file was wrong in the exact way this task is about, and the scanner did not tell me. Gitleaks combines the fields of an allowlist with **OR** by default, so listing `paths` and `regexes` together does not mean "this value in this file" — it means "this file, *or* this value anywhere". The file went green, and I had quietly excluded all of `submissions/lab3.md` from scanning while believing I had pinned two strings. The fix is one line, `condition = "AND"`, and the lesson is that a tune-out which is too wide looks exactly like a tune-out that works: both produce a passing scan. The `detect-private-key` hook has no allowlist mechanism at all, so the only options there were excluding the file or not writing the armour line; I rephrased the sentence, which is the smaller loss.

I verified the narrowed version rather than trusting it, by appending a *different* fake PAT to the same allowlisted file:

```bash
$ gitleaks git --staged --no-banner            # the report as committed
INF no leaks found

$ printf 'ghp_9Z8y7X6w...<a different 36-char value>\n' >> submissions/lab3.md
$ git add submissions/lab3.md && gitleaks git --staged --no-banner -v
RuleID:      github-pat
Line:        201
WRN leaks found: 1
```

A new secret in the allowlisted file is still caught. (The value is truncated above on purpose: pasting it in full would have needed a third allowlist entry, and the hook blocked this very commit until I shortened it — the cheapest fix for a false positive is usually not writing the secret down.) That is the test that separates "I pinned two values" from "I stopped scanning this file", and it is the one I should have run before the first version went green.

The general lesson is the one the question was driving at: every tune-out is a hole, and the only question is how precisely you can aim it.

## Bonus

### Before and after

```bash
$ git log --oneline          # before
a596e46 docs: usage notes
2981c38 feat: empty log
2746782 feat: add config
f2482d0 init

$ git log -p | grep -c 'ghp_AAAA'
2
```

```bash
$ git filter-repo --replace-text /tmp/replace.txt --force
Parsed 4 commits
New history written in 0.05 seconds; now repacking/cleaning...
Repacking your repo and cleaning out old unneeded objects
Completely finished after 0.15 seconds.

$ git log --oneline          # after
203f642 docs: usage notes
0e27b7e feat: empty log
ceec6b1 feat: add config
f2482d0 init

$ git log -p | grep -c 'ghp_AAAA'
0
$ git log -p | grep -c 'REDACTED'
2
```

Counts went 2 → 0 for the secret and 0 → 2 for the marker, as required.

### The refusal

```
Aborting: Refusing to destructively overwrite repo history since
this does not look like a fresh clone.
  (expected at most one entry in the reflog for HEAD)
Please operate on a fresh clone instead.  If you want to proceed
anyway, use --force.
```

I re-ran with `--force`. The reasoning behind the refusal is worth stating rather than working around blindly: filter-repo rewrites every commit object, so any reference that still points at the old objects — another branch, a stash, a colleague's clone — silently diverges, and the tool cannot tell a throwaway sandbox from someone's only copy of a repository. Its heuristic is the HEAD reflog, and it wants a fresh clone because a fresh clone has nothing else pointing at the old history. In a sandbox I created four commits ago that guarantee is trivially true, so `--force` is the documented answer here. In a real repository the honest path is a fresh clone, exactly as the message says.

### Rewriting history is step one

**Step two is rotating the credential** — revoking the token at the provider and issuing a new one.

The rewrite only removes the string from *my* copy of the history. The old objects still exist in every clone, in every fork, in GitHub's own unreachable-object storage (a blob stays reachable by its SHA through the web UI and the API long after no ref points to it), in CI caches and in whatever scraper indexed the repository between the push and the cleanup. Public-repo secret scrapers work in seconds, so the realistic assumption is that the token was harvested before the rewrite even started. Rotation is what actually ends the incident, because it makes the leaked value worthless regardless of how many copies exist. The rewrite is hygiene; the rotation is the fix.

### Two things that surprised me

1. **The root commit kept its hash.** All three later commits changed (`a596e46 → 203f642`, `2981c38 → 0e27b7e`, `2746782 → ceec6b1`), but `f2482d0 init` is byte-identical before and after. I expected a history rewrite to mean *every* hash changes. It does not: a commit's hash depends on its tree, its message and its parents, and the empty root commit had no content touched by the replacement and no parent to inherit a new hash from. Everything downstream of a change is rewritten; everything upstream of it is not.

2. **filter-repo deleted the `origin` remote** — `git remote -v` prints nothing afterwards. I expected a text-replacement tool to touch history and leave configuration alone. It is deliberate: removing the remote makes it impossible to accidentally `git push` a rewritten history over a shared branch without consciously re-adding the remote first. A real cleanup therefore ends with `git remote add origin ...` followed by a force push — which is also the moment every collaborator's clone needs re-cloning.
