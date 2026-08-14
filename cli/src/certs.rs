//! `parda-cli gen-certs` — the certificate material a real deployment
//! needs, and nothing else.
//!
//! ## What this produces, and where each piece goes
//!
//! | File | Secret? | Belongs on |
//! |------|---------|------------|
//! | `authority-cert.pem` | no | the client — bundled into the APK as its sole trust anchor |
//! | `authority-key.pem` | **yes** | the operator's machine only |
//! | `relay-chain.pem` | no | the relay host (`PARDA_TLS_CERT_PATH`) |
//! | `relay-key.pem` | **yes** | the relay host (`PARDA_TLS_KEY_PATH`) |
//!
//! ## The authority is reused, deliberately
//!
//! Running this a second time in the same directory reissues the relay
//! certificate but **keeps the existing authority**. That is the entire
//! operational point of `parda_tls::pinned_authority`: every client that
//! already has `authority-cert.pem` compiled in keeps working across a
//! host move, a key rotation, or an added SAN, because the thing they
//! pinned did not change. Regenerating the authority instead would
//! silently invalidate every installed app, and the failure would show up
//! as "nobody can connect any more" long after the command that caused
//! it.
//!
//! Replacing the authority is therefore made explicit — `--new-authority`
//! — rather than being what happens when you forget a flag.

use std::path::{Path, PathBuf};

use parda_tls::PinnedAuthority;

const AUTHORITY_CERT: &str = "authority-cert.pem";
const AUTHORITY_KEY: &str = "authority-key.pem";
const RELAY_CHAIN: &str = "relay-chain.pem";
const RELAY_KEY: &str = "relay-key.pem";

pub fn run(sans: Vec<String>, out_dir: PathBuf, new_authority: bool) {
    if sans.is_empty() {
        eprintln!(
            "gen-certs needs at least one --san: the hostname or IP address clients will use to \
             reach the relay. A certificate naming nothing matches nothing."
        );
        std::process::exit(2);
    }

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("could not create {}: {e}", out_dir.display());
        std::process::exit(1);
    }

    let authority = match load_or_create_authority(&out_dir, new_authority) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let (chain, key) = match parda_tls::relay_certificate(&authority, &sans) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("could not issue the relay certificate: {e}");
            std::process::exit(1);
        }
    };

    write_public(&out_dir.join(RELAY_CHAIN), &chain);
    write_secret(&out_dir.join(RELAY_KEY), &key);

    let dir = out_dir.display();
    println!("Issued a relay certificate for: {}", sans.join(", "));
    println!();
    println!("  {dir}/{AUTHORITY_CERT}   -> bundle into the app (public)");
    println!("  {dir}/{AUTHORITY_KEY}    -> KEEP HERE. Never upload this.");
    println!("  {dir}/{RELAY_CHAIN}      -> copy to the relay host");
    println!("  {dir}/{RELAY_KEY}        -> copy to the relay host (secret)");
    println!();
    println!("On the relay host:");
    println!("  export PARDA_TLS_ENABLED=1");
    println!("  export PARDA_TLS_CERT_PATH=/path/to/{RELAY_CHAIN}");
    println!("  export PARDA_TLS_KEY_PATH=/path/to/{RELAY_KEY}");
    println!();
    println!("In the app build:");
    println!("  cp {dir}/{AUTHORITY_CERT} mobile/android/app/src/main/res/raw/parda_relay_ca.pem");
    println!("  echo 'relayHost={}' > mobile/android/relay.properties", sans[0]);
    println!();
    println!(
        "Anyone holding {AUTHORITY_KEY} can mint a certificate every installed client accepts, \
         and there is no revocation path short of shipping a new app. Treat it like the release \
         signing key."
    );
}

fn load_or_create_authority(
    out_dir: &Path,
    new_authority: bool,
) -> Result<PinnedAuthority, String> {
    let cert_path = out_dir.join(AUTHORITY_CERT);
    let key_path = out_dir.join(AUTHORITY_KEY);
    let exists = cert_path.exists() && key_path.exists();

    if exists && new_authority {
        return Err(format!(
            "--new-authority would overwrite {}, and every client that already pinned it would \
             stop being able to connect. Move the existing files aside first if that is genuinely \
             what you want.",
            cert_path.display()
        ));
    }

    if exists {
        let certificate_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| format!("could not read {}: {e}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| format!("could not read {}: {e}", key_path.display()))?;
        println!("Reusing the existing authority in {} — already-installed clients keep working.", out_dir.display());
        return Ok(PinnedAuthority { certificate_pem, key_pem });
    }

    // Exactly one half present means a previous run was interrupted or a
    // file was moved. Generating a fresh authority here would look like
    // success and quietly orphan every installed client, so refuse.
    if cert_path.exists() || key_path.exists() {
        return Err(format!(
            "{} contains one half of an authority ({} without its counterpart). Refusing to \
             generate a new one over it: if the surviving half is the certificate your clients \
             pinned, replacing it would lock all of them out.",
            out_dir.display(),
            if cert_path.exists() { AUTHORITY_CERT } else { AUTHORITY_KEY }
        ));
    }

    let authority = parda_tls::pinned_authority()
        .map_err(|e| format!("could not generate the authority: {e}"))?;
    write_public(&cert_path, &authority.certificate_pem);
    write_secret(&key_path, &authority.key_pem);
    println!("Generated a new authority in {}.", out_dir.display());
    Ok(authority)
}

fn write_public(path: &Path, contents: &str) {
    if let Err(e) = std::fs::write(path, contents) {
        eprintln!("could not write {}: {e}", path.display());
        std::process::exit(1);
    }
}

/// Write a private key, readable only by its owner where the platform
/// supports saying so.
///
/// Mirrors `mixnode/src/identity.rs`'s handling of the mix node's own
/// secret key: 0600 on Unix, and on Windows the file inherits the
/// directory's ACL, which this cannot tighten without a dependency. That
/// difference is stated rather than left implied — a key written here on
/// Windows is exactly as protected as the directory it sits in.
fn write_secret(path: &Path, contents: &str) {
    write_public(path, contents);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            eprintln!("warning: could not restrict permissions on {}: {e}", path.display());
        }
    }
}
