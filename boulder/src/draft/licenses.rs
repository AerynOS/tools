// SPDX-FileCopyrightText: Copyright © 2020-2025 Serpent OS Developers
//
// SPDX-License-Identifier: MPL-2.0

use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::path::PathBuf;

use jwalk::WalkDir;
use rapidfuzz::distance::levenshtein;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tui::Styled;

pub struct LicenceMatch {
    pub spdx_identifier: String,
    pub confidence: f64,
}

pub type Error = Box<dyn std::error::Error>;

fn collect_spdx_licenses(dir: &Path) -> Result<(HashSet<PathBuf>, HashSet<PathBuf>), Error> {
    // Collect our spdx licenses to compare against ensuring we don't match against deprecated licenses.
    let mut purified_spdx_licenses = HashSet::new();
    let spdx_license_paths: HashSet<_> = fs::read_dir(dir)?
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                if !e.file_name().to_str().unwrap_or_default().contains("deprecated_") {
                    purified_spdx_licenses.insert(PathBuf::from(e.file_name()));
                    Some(e.path())
                } else {
                    None
                }
            })
        })
        .collect();

    Ok((purified_spdx_licenses, spdx_license_paths))
}

fn collect_dir_licenses(
    dir: &Path,
    spdx_list: &HashSet<PathBuf>,
) -> Result<(HashSet<PathBuf>, HashSet<PathBuf>), Error> {
    let patterns = ["copying", "license", "licence"];

    // Match potential license files
    let mut licenses = HashSet::new();
    let mut hash_direntries = HashSet::new();

    for entry in WalkDir::new(dir).max_depth(4) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let file_name = PathBuf::from(entry.file_name());
            hash_direntries.insert(file_name);

            let file_name = entry.file_name().to_string_lossy().to_lowercase();
            if patterns.iter().any(|&pattern| file_name.contains(pattern)) {
                licenses.insert(entry.path());
            }

            // Split the spdx licence e.g. GPL-2.0-or-later -> GPL then check
            // if the file name contains the split value, if it does
            // add it to our licences to check against.
            let file_name_contains_licence: Vec<_> = spdx_list
                .par_iter()
                .filter_map(|license| match license.to_string_lossy().split_once("-") {
                    Some((key, _)) => {
                        if file_name.starts_with(&key.to_lowercase()) {
                            Some(license)
                        } else {
                            None
                        }
                    }
                    None => None,
                })
                .collect();

            if !file_name_contains_licence.is_empty() {
                licenses.insert(entry.path());
            }
        }
    }

    Ok((licenses, hash_direntries))
}

fn remove_code_comments(line: &str) -> String {
    let re = Regex::new(r"(/\*|\*/|//|#|--|<!--|-->|\{-|-}|\(\*|\*\)|'''|\|%)").unwrap();
    let sanitized = re.replace_all(line, "").to_string();
    sanitized.trim().to_owned()
}

fn search_in_files(dir: &Path, search_terms: &[&str]) -> io::Result<bool> {
    let mut i = 0;
    for entry in WalkDir::new(dir).max_depth(3) {
        i += i;
        if i == 50 {
            return Ok(false);
        }
        let entry = entry?;
        if entry.file_type().is_file() {
            if let Ok(file) = fs::File::open(entry.path()) {
                let reader = io::BufReader::new(file);

                let mut result = String::with_capacity(1024);

                for line in reader.lines().take(15) {
                    let line = line?;
                    result.push_str(&line);
                }

                // Code comment deliminators may be in-between our search terms
                let sanitized = remove_code_comments(result.as_str());

                if search_terms.iter().any(|term| sanitized.contains(term)) {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

pub fn match_licences(dir: &Path, spdx_dir: &Path) -> Result<Vec<LicenceMatch>, Error> {
    let (spdx_pure, spdx_paths) = collect_spdx_licenses(spdx_dir)?;
    let (licenses, dir_entries) = collect_dir_licenses(dir, &spdx_pure)?;

    let reuse_matches: Vec<_> = dir_entries
        .intersection(&spdx_pure)
        .map(|m| LicenceMatch {
            spdx_identifier: m.with_extension("").to_str().unwrap_or_default().to_owned(),
            confidence: 100.0,
        })
        .collect();

    if !reuse_matches.is_empty() {
        return Ok(reuse_matches);
    }

    if licenses.is_empty() {
        println!("{} | Failed to find any licenses", "Warning".yellow());
        return Ok(vec![]);
    }

    let confidence_cutoff = 0.9;

    let license_matches: Vec<_> = licenses
        .par_iter()
        .filter_map(|license| {
            let license_content = fs::read_to_string(license).ok();
            if license_content.is_some() {
                Some(license_content)
            } else {
                println!("{} | Failed to parse {}", "Warning".yellow(), license.display());
                None
            }
        })
        .flat_map(|content| {
            let sanitized = content
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let scorer = levenshtein::BatchComparator::new(sanitized.chars());
            spdx_paths.par_iter().filter_map(move |spdx_license| {
                // For GNU derivate licenses SPDX includes a copy of the general GNU license below the
                // derivate license whereas downstream tarballs will typically only contain the derivate license.
                // This ruins the algorithms, just truncate to the .len() plus an additional 5% (to account for subtle
                // license variants) of the file we're comparing against to get around it.
                // NOTE: Although only reading up to n lines/chars would be quicker it has difficulty differentiating
                //       between subtle differences e.g. Apache-2.0 vs Pixar or GFDL-1.2-* vs GFDL-1.3-*.
                // TODO: How to match against multiple licences in one file? hybrid sliding window approach approach?
                let truncated_canonical: String = fs::read_to_string(spdx_license)
                    .ok()?
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .chars()
                    .take((sanitized.chars().count() as f64 * 1.05) as usize)
                    .collect();
                let lev_sim = scorer.normalized_similarity_with_args(
                    truncated_canonical.chars(),
                    &levenshtein::Args::default().score_cutoff(confidence_cutoff),
                )?;

                if lev_sim < confidence_cutoff {
                    return None;
                }

                let sanitized_spdx_license = spdx_license
                    .with_extension("")
                    .file_name()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
                    .to_owned();

                // Annoying ass crap to drop GNU -only licence variants that can only be resolved
                // by reading the standard licence header or hoping the SPDX licence identifier exists
                // at the top of the file, we currently do not verify -or-later licences as they are common.
                // TODO: Drop the -or-later licence if we actually match
                if sanitized_spdx_license.contains("-only") {
                    let search_terms = [
                        "any later version",
                        &sanitized_spdx_license.replace("-only", "-or-later"),
                    ];
                    if search_in_files(dir, &search_terms).ok()? {
                        return None;
                    }
                }

                Some(LicenceMatch {
                    spdx_identifier: sanitized_spdx_license,
                    confidence: lev_sim * 100.0,
                })
            })
        })
        .collect();

    if license_matches.is_empty() {
        println!("{} | Failed to match against any licenses", "Warning".yellow());
        return Ok(vec![]);
    }

    Ok(license_matches)
}
