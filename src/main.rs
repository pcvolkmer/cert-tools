/*
 * This file is part of cert-tools
 *
 * Copyright (C) 2025 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

mod chain;
mod cli;

use crate::chain::{print_cert, Chain, PrivateKey};
use crate::cli::{Cli, SubCommand};
use clap::Parser;
use console::style;
use itertools::Itertools;
use std::cmp::Ordering;
use std::path::Path;

fn main() -> Result<(), ()> {
    let cli = Cli::parse();

    match cli.cmd {
        SubCommand::Print { cert, ca, key } => {
            let chain = Chain::read(Path::new(&cert));

            if let Ok(mut chain) = chain {
                if let Some(ca) = ca {
                    if let Ok(ca_chain) = Chain::read(Path::new(&ca)) {
                        for ca_cert in ca_chain.to_vec() {
                            chain.push(ca_cert);
                        }
                    } else {
                        println!("{}", style(format!("Cannot read file: {}", ca)).red());
                        return Err(());
                    }
                }

                for cert in chain.certs() {
                    print_cert(cert);
                    println!()
                }

                if chain.has_missing_tail() {
                    println!(
                        "{}\n  Self signed (CA-) Certificate? It might be required to import a self signed Root-CA manually for applications to use it.",
                        style("! Last Certificate points to another one that should be contained in chain.").yellow()
                    );
                }

                if chain.is_valid() {
                    println!("{}", style("✓ Chain is valid").green());
                } else {
                    println!(
                        "{}",
                        style("! Chain or some of its parts is not valid (anymore)").red()
                    );
                }

                if let Some(key) = key {
                    match PrivateKey::read(Path::new(&key)) {
                        Ok(private_key) => {
                            if let Some(cert) = chain.certs().first() {
                                if cert.public_key_matches(private_key) {
                                    println!(
                                        "{}",
                                        style("✓ Private Key matches first Cert Public Key")
                                            .green()
                                    )
                                } else {
                                    println!("{}", style("! Private Key does not match the first Cert Public Key").red())
                                }
                            }
                        }
                        _ => {
                            println!("{}", style("Could not read Private Key").red())
                        }
                    }
                }
            } else {
                println!("{}", style(format!("Cannot read file: {}", cert)).red());
                return Err(());
            }
        }
        SubCommand::Merge { cert, ca } => {
            let chain = Chain::read(Path::new(&cert));

            if let Ok(mut chain) = chain {
                if let Some(ca) = ca {
                    if let Ok(ca_chain) = Chain::read(Path::new(&ca)) {
                        for ca_cert in ca_chain.to_vec() {
                            chain.push(ca_cert);
                        }
                    } else {
                        eprintln!("{}", style(format!("Cannot read file: {}", ca)).red());
                        return Err(());
                    }
                }
                if !chain.is_valid() {
                    eprintln!(
                        "{}",
                        style("Cannot merge files to valid chain - try to sort unique certs")
                            .yellow()
                    );
                }
                let mut certs = chain.to_vec();
                certs.sort_by(|cert1, cert2| {
                    if cert1.subject_key_id() == cert2.authority_key_id() {
                        return Ordering::Greater;
                    } else {
                        return Ordering::Less;
                    }
                });
                let chain = Chain::from(certs.into_iter().unique().collect::<Vec<_>>());
                if !chain.is_valid() {
                    eprintln!(
                        "{}",
                        style("Cannot merge files to valid chain - giving up!").red()
                    );
                    return Err(());
                }
                for cert in chain.certs() {
                    match cert.to_pem() {
                        Ok(plain) => print!("{}", plain),
                        Err(_) => {
                            eprintln!(
                                "{}",
                                style("Cannot merge files to valid chain - Cert error!").red()
                            );
                            return Err(());
                        }
                    }
                }
            } else {
                eprintln!("{}", style(format!("Cannot read file: {}", cert)).red());
                return Err(());
            }
            eprintln!("{}", style("Success!").green());
        }
    }
    Ok(())
}
