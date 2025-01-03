// SPDX-FileCopyrightText: Copyright © 2020-2024 Serpent OS Developers
//
// SPDX-License-Identifier: MPL-2.0

//! Boot management integration in moss

use std::{
    io,
    path::{Path, PathBuf},
    str::FromStr,
};

use blsforme::{
    os_release::{self, OsRelease},
    CmdlineEntry, Entry,
};
use fnmatch::Pattern;
use fs_err as fs;
use stone::payload::{layout, Layout};
use thiserror::{self, Error};

use crate::{package::Id, Installation, State};

#[derive(Debug, Error)]
pub enum Error {
    #[error("blsforme: {0}")]
    Blsforme(#[from] blsforme::Error),

    #[error("io: {0}")]
    IO(#[from] io::Error),

    #[error("os_release: {0}")]
    OsRelease(#[from] os_release::Error),

    /// fnmatch pattern compilation for boot, etc.
    #[error("fnmatch pattern: {0}")]
    Pattern(#[from] fnmatch::Error),

    #[error("incomplete kernel tree: {0}")]
    IncompleteKernel(String),
}

/// Simple mapping type for kernel discovery paths, retaining the layout reference
#[derive(Debug)]
struct KernelCandidate<'a> {
    path: PathBuf,
    _layout: &'a Layout,
}

impl AsRef<Path> for KernelCandidate<'_> {
    fn as_ref(&self) -> &Path {
        self.path.as_path()
    }
}

/// From a given set of input paths, produce a set of match pairs
/// NOTE: This only works for a *new* blit and doesn't retroactively
/// sync old kernels!
fn kernel_files_from_state<'a>(
    install: &Installation,
    layouts: &'a [(Id, Layout)],
    pattern: &'a Pattern,
) -> Vec<KernelCandidate<'a>> {
    let mut kernel_entries = vec![];

    for (_, path) in layouts.iter() {
        match &path.entry {
            layout::Entry::Regular(_, target) => {
                if pattern.match_path(target).is_some() {
                    kernel_entries.push(KernelCandidate {
                        path: install.root.join("usr").join(target),
                        _layout: path,
                    });
                }
            }
            layout::Entry::Symlink(_, target) => {
                if pattern.match_path(target).is_some() {
                    kernel_entries.push(KernelCandidate {
                        path: install.root.join("usr").join(target),
                        _layout: path,
                    });
                }
            }
            _ => {}
        }
    }

    kernel_entries
}

/// Find bootloader assets
fn boot_files_from_state<'a>(
    install: &Installation,
    layouts: &'a [(Id, Layout)],
    pattern: &'a Pattern,
) -> Vec<PathBuf> {
    let mut rets = vec![];

    for (_, path) in layouts.iter() {
        if let layout::Entry::Regular(_, target) = &path.entry {
            if pattern.match_path(target).is_some() {
                rets.push(install.root.join("usr").join(target));
            }
        }
    }

    rets
}

pub fn synchronize(install: &Installation, state: &State, layouts: &[(Id, Layout)]) -> Result<(), Error> {
    let root = install.root.clone();
    let is_native = root.to_string_lossy() == "/";
    // Create an appropriate configuration
    let config = blsforme::Configuration {
        root: if is_native {
            blsforme::Root::Native(root.clone())
        } else {
            blsforme::Root::Image(root.clone())
        },
        vfs: "/".into(),
    };

    let pattern = Pattern::from_str("lib/kernel/(version:*)/*")?;
    let systemd = Pattern::from_str("lib*/systemd/boot/efi/*.efi")?;
    let booty_bits = boot_files_from_state(install, layouts, &systemd);

    // No kernels? No bother.
    let kernels = kernel_files_from_state(install, layouts, &pattern);
    if kernels.is_empty() {
        return Ok(());
    }
    // no fun times
    if booty_bits.is_empty() {
        return Ok(());
    }

    // Read the os-release file we created
    let fp = fs::read_to_string(install.root.join("usr").join("lib").join("os-release"))?;
    let os_release = OsRelease::from_str(&fp)?;
    let schema = blsforme::Schema::Blsforme {
        os_release: &os_release,
    };
    let discovered = schema.discover_system_kernels(kernels.iter())?;

    // pipe all of our entries into blsforme
    let mut entries = discovered
        .iter()
        .map(|d| {
            let id = i32::from(state.id);
            Entry::new(d)
                .with_cmdline(CmdlineEntry {
                    name: "---fstx---".to_owned(),
                    snippet: format!("moss.fstx={id}"),
                })
                .with_state_id(id)
        })
        .collect::<Vec<_>>();
    for entry in entries.iter_mut() {
        if let Err(e) = entry.load_cmdline_snippets(&config) {
            log::warn!("Failed to load cmdline snippets: {}", e);
        }
    }

    // If we can't get a manager, find, but don't bomb. Its probably a topology failure.
    let manager = match blsforme::Manager::new(&config) {
        Ok(m) => m.with_entries(entries.into_iter()).with_bootloader_assets(booty_bits),
        Err(_) => return Ok(()),
    };

    // Only allow mounting pre-sync for a native run
    if is_native {
        let _mounts = manager.mount_partitions()?;
        manager.sync(&schema)?;
    } else {
        manager.sync(&schema)?;
    }

    Ok(())
}
