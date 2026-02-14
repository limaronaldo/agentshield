mod arbitrary_file_access;
mod command_injection;
mod credential_exfil;
mod runtime_install;
mod self_modification;
mod ssrf;

use super::Detector;

/// Returns all built-in detectors for the v0.1 rule set.
pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(command_injection::CommandInjectionDetector),
        Box::new(credential_exfil::CredentialExfilDetector),
        Box::new(ssrf::SsrfDetector),
        Box::new(arbitrary_file_access::ArbitraryFileAccessDetector),
        Box::new(runtime_install::RuntimeInstallDetector),
        Box::new(self_modification::SelfModificationDetector),
    ]
}
