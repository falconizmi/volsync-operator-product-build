# Triaging golang.org/x/crypto CVEs for VolSync

## x/crypto vs x/crypto/ssh — know the difference

golang.org/x/crypto is one Go module containing many subpackages. A CVE
targets a specific subpackage, and each submodule imports different ones:

| Submodule  | x/crypto subpackages imported                     |
|------------|---------------------------------------------------|
| rclone     | ssh, ssh/knownhosts, nacl/secretbox, scrypt        |
| volsync    | argon2, openpgp, poly1305, scrypt                  |
| syncthing  | bcrypt, chacha20poly1305, hkdf, scrypt             |
| diskrsync  | blake2b                                            |

Key takeaway: only rclone imports x/crypto/ssh. So for any CVE in
x/crypto/ssh, x/crypto/ssh/agent, or x/crypto/ssh/knownhosts, only
rclone needs investigation. For CVEs in other subpackages (bcrypt,
scrypt, argon2, etc.), check which submodules import that subpackage.

## Walkthrough: triaging an x/crypto/ssh CVE

### Step 1 — Identify the affected subpackage and symbols

Look up the CVE in the Go vulnerability database:
- https://pkg.go.dev/vuln/ — search by CVE ID or GO-20XX-XXXX ID

Note:
- Which subpackage (ssh, ssh/agent, ssh/knownhosts)
- Which symbols are affected (e.g. CertChecker, NewServerConn, client.Add)
- The fix version

### Step 2 — Is it server-side only, client-side, or shared?

This is the most important question for x/crypto/ssh CVEs.

**Server-side only** — code paths entered through ssh.NewServerConn or
ServerConfig callbacks. VolSync never runs an SSH server ("rclone serve
sftp" is never invoked). These are unreachable.

Server-side indicators:
- NewServerConn, ServerConfig, ServerConn
- PublicKeyCallback on a ServerConfig
- CertChecker (used as server-side PublicKeyCallback)
- PartialSuccessError (server auth callback)

**Client-side** — code paths used when connecting to a remote SSH server.
Reachable when a user configures an SFTP backend via RcloneConfig.

Client-side indicators:
- NewClientConn, Dial, ClientConfig
- Session.* methods (Run, Shell, Start, etc.)
- knownhosts.* (host key verification)
- ssh-agent Signers() calls

**Shared** — code used by both client and server. If a CVE is in shared
code, it is client-side reachable.

Shared code indicators:
- ssh/keys.go (key parsing — both sides parse keys)
- ssh/mux.go (connection multiplexer — both sides use it)
- ssh/handshake.go (used by both client and server handshake)

### Step 3 — Does rclone use the specific affected symbol?

Even if a CVE is client-side, rclone might not use the specific symbol.

    grep -rn "SymbolName" rclone/ --include='*.go'

Zero matches = not affected, regardless of client/server classification.

Examples of symbols rclone does NOT use:
- CertChecker (rclone uses a plain PublicKeyCallback function)
- agent.Add, ForwardToRemote, ForwardToAgent (rclone only reads signers
  via Signers(), never adds/forwards keys)

Examples of symbols rclone DOES use:
- ssh.NewClientConn (sftp/ssh_internal.go:42)
- knownhosts.New (sftp/sftp.go:943)
- sshAgentClient.Signers (sftp/sftp.go:980)
- ssh.ParseAuthorizedKey (sftp/sftp.go:1011)

### Step 4 — Decision

| Server-side only? | Symbol used by rclone? | Verdict      |
|--------------------|----------------------|--------------|
| Yes                | —                    | Not affected |
| No (client/shared) | No                   | Not affected |
| No (client/shared) | Yes                  | Affected     |

## Common pitfalls

1. **"VolSync doesn't reference SFTP"** — irrelevant. Users supply
   rclone.conf at runtime via RcloneConfig. The SFTP backend is compiled
   into the binary.

2. **"It's an SSH vulnerability and we don't use SSH"** — rclone's SFTP
   backend IS an SSH client under the hood.

3. **Confusing shared code with server-only code** — some code (key parser,
   mux) is used by both sides. A CVE description mentioning "server" does
   not mean the code is server-only. Check the actual code path.

4. **Skipping the symbol check** — even for client-side CVEs, always grep.
   Some client-side symbols (agent.Add) are never used by rclone.

## Relevant rclone source files

- backend/sftp/sftp.go — SFTP client: knownhosts, ssh-agent, config
- backend/sftp/ssh_internal.go — ssh.NewClientConn, ssh.NewClient
- cmd/serve/sftp/server.go — "rclone serve sftp" (server-side, NOT used
  by VolSync)

## Fix mechanism

Fixes are applied via CVE-patches/rclone_patch_deps/go.mod using Go replace
directives. The replace overrides the version at build time regardless of
what the require block says. Steps:

1. cd rclone
2. Add the replace directive to rclone/go.mod (keep existing replaces)
3. Run go mod tidy
4. cd ..
5. cp rclone/go.mod CVE-patches/rclone_patch_deps/go.mod
6. cp rclone/go.sum CVE-patches/rclone_patch_deps/go.sum
7. Update the comment in CVE-patches/patch_rclone.sh
8. git checkout rclone (restore submodule)
9. Commit and open PR against the release branch
