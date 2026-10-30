# git-veil

git-veil stores encrypted secrets in a git repository. It is written in Rust.
It encrypts files using [`age`][age] identity keys (via the pure-Rust
[`age` crate][age-crate]). The public parts of the identities are committed
into the git repo. That keyring of `age` public keys is signed with an
[Ed25519][ed25519] (via [`ed25519-dalek`][dalek]) key pair you generate
using `openssl`.

In the following, `age` refers to the open source `age` encryption tooling,
which may be installed separately to securely create and maintain
cryptographic keys outside of the git repo; the `git-veil` software uses the
Rust `rage` library to work with the keys.

The `age` format is an encryption format designed by Filippo Valsorda.
This means that `git-veil`'s ciphertexts are standard `age` encrypted files.
Any compliant `age` tool can decrypt them.

[age]: https://age-encryption.org
[age-crate]: https://crates.io/crates/age
[ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
[dalek]: https://crates.io/crates/ed25519-dalek

## Why

The point of `git-veil` is that your application deployment secret material
is versioned alongside the code. The ciphertexts are committed, so every
clone carries the exact secrets that work with that version of the code.
The plaintext never has to leave your machine to reach a build box: you
simply create an `age` identity file per CI pipeline or per environment or
per VM. Then your deployment script or your production server can run
`git-veil reveal` to use its own `age` identity to decrypt the secrets your
code needs.

Under such a model you should `ssh` into your dev, test and prod
environments and run the commands to create the `age` identity in that
environment. You do not need to look at the secret part of the key nor cut
and paste it or transmit it. You simply copy the public part of the key and
pass it to `git-veil add-key`.

The preceding paragraphs may read like a very radical idea. Yet consider
the alternatives; you have to maintain a system to distribute and backup
your deployment secrets. Your author is shocked at how many software
platforms (e.g. mobile application tooling, mobile backend) have you commit
plaintext certificates into a private git database. Your author has seen
and used a lot of enterprise systems where certificates and crypto
materials were supposed to be automated. In practice your author has often
seen them stepped around:

- Testing the final deployment of production keys into production takes
  time and effort, and just as you got it right in some test environment
  does not mean it is going to go right first time in pro. `git-veil` means
  that your secret management pipeline is your code deployment pipeline.
- The moment doing things "properly" is not "just works" people end up
  cutting/pasting/emailing the certs, passwords or keys around. The effort
  of getting your keys securely deployed should not be left at the point
  when you are under pressure to go live. The effort of `git-veil` is in
  the initial setup and in learning how to use it. Once you know the drill
  you can move to a model where your deployment secrets are not being
  pasted over slack channels.
- Your author has many times seen crypto materials expiring some months
  past go-live and lots of lost time and bad optics on trying to
  retroactively fix the mess. This is why your author added automated
  testing to the mighty git-secret project. Perfection, and complexity, is
  the enemy of secure.
- Your author is convinced that the net result is quite a lot of security
  theatre and security-by-obscurity. Or even the worst of all worlds; a
  central secret management tool that is a concentration risk combined with
  work arounds that are pasting around certs when sites go down a year
  after go-live.

The aim of `git-veil` is to bring self-sovereign public-key encryption of
your application deployment secrets to the masses. History tells us that it
is developer hubris to build your own security tooling. Leave it to the
professional cryptographers working in the open with other professional
cryptographers. Your author's response to the charge of hubris is to ask
that you hold my beer; but first buy me a beer for you to hold. By which I
mean raise me a PR and join the discussion.

## How it works

Three ideas carry the whole design.

1. **Encryption in place.** `hide` turns `.env` into `.env.secret`, a
   standard `age` file encrypted to every key in the keyring, and deletes
   the plaintext. You gitignore the plaintext names and commit the
   `.secret` files. `reveal` brings a plaintext back.
2. **A signed keyring.** `.git-veil/keyring` names who can decrypt. It is
   signed with the repository owner's Ed25519 key. Every gated command
   verifies that signature against a pin held in your local key store
   before it touches anything. A keyring edited by a non-owner fails
   closed.
3. **A per-machine pin.** Trust is anchored on each machine by a
   possession proof: you can only pin the owner key on a machine that
   holds the matching signing seed. Machines without the seed import a
   pin-file that travelled out of band. The pin lives outside the
   repository and is never committed.

## The two keys

You need two keys before you start. git-veil generates neither, because a
key the tool created would be a key you never backed up.

- An X25519 private key for encryption, made with `age-keygen` or
  `rage-keygen`. The public half is shared; the private half is never
  committed.
- An Ed25519 signing key for the keyring, needed only by whoever owns the
  repository. This is not an `age` key, and no `age` tool makes it. You
  make it with `openssl`.

Step 1 of the [Solo guide](solo.md) has the exact commands, and the backup
ritual. Do it once, back both private halves up in a password manager, and
you will never lose a ciphertext.

## Getting started

Install the binary first: see [Installation](installation.md). Then, in the
root of a git repository:

```sh
git-veil init ~/.git-veil/owner.verifying        # creates .git-veil/ state and pins the owner key
git-veil import private-key.txt                 # your X25519 private key, made by age-keygen
git-veil repo-id                                # prints the ID trust wants, e.g. demo+example@github.com
git-veil export age1xxxx                        # your public key string
git-veil add-key example@github.com age1xxxx    # adds you to the signed keyring
printf 'API_KEY=hunter2\n' > .env
git-veil add-file .env                          # tracks it, gitignores the plaintext name
git-veil hide .env                              # encrypts to the keyring; deletes the plaintext
git add .gitignore .git-veil .env.secret
git commit -m "Add encrypted secrets"
git-veil reveal .env                            # brings it back when you need to edit
```

Every command's behaviour, flags and exit codes are documented in
[Commands](commands.md). Two refusals are worth knowing before they
surprise you: `init` will not reset a repository with established trust,
and `hide` asks before it first-encrypts a path someone else nominated in
the tracking manifest. You answer with
[allow](commands.md#allow).

## The daily cycle

Name the file you are working with. Every `hide` and `reveal` names its
file(s); the command acts on exactly the paths you give it, so the commit
shows what you actually touched:

```sh
git-veil reveal .env          # decrypt one file in place to edit
... edit .env ...
git-veil changes              # diff plaintext against the last hidden version
git-veil hide .env            # re-encrypt one file; every other ciphertext is untouched
git add .env.secret && git commit -m "Rotate API key"
```

`cat .env` peeks at stdout without touching disk state. `list` shows what
is tracked, `list-keys` shows who can decrypt, `verify-keys` and
`changes` are the health checks. The [Solo guide](solo.md) walks the whole
loop with real output.

## Where next

- [Solo](solo.md) - the solo setup, end to end, including a build box that
  reveals on its own key.
- [Team](team.md) - sharing a repository: joining, day-to-day collaboration
  and departing.
- [Commands](commands.md) - every command documented: options, behaviour
  and exit codes.
- [Troubleshooting](troubleshooting.md) - key store permissions, the trust
  and rotate failure stories, and recovery.
- [Design specification](design.md) - how trust anchoring, pinning and
  keyring signing work under the hood.
