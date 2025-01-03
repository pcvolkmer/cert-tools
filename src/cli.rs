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

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
#[command(arg_required_else_help(true))]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Subcommand)]
pub enum SubCommand {
    #[command(
        name = "print",
        about = "Gibt Übersicht zu den angegebenen Dateien aus"
    )]
    Print {
        #[arg(help = "Datei mit Zertifikaten im PEM-Format")]
        cert: String,
        #[arg(help = "Datei mit Private Key im PEM-Format (Optional)")]
        key: Option<String>,
        #[arg(long, help = "Datei mit CA im PEM-Format (Optional)")]
        ca: Option<String>,
    },
    #[command(
        name = "merge",
        about = "Fügt Zertifikats- mit CA-Datei zusammen und sortiert die Zertifikate, wenn erforderlich"
    )]
    Merge {
        #[arg(help = "Datei mit Zertifikaten im PEM-Format")]
        cert: String,
        #[arg(help = "Datei mit CA im PEM-Format")]
        ca: Option<String>,
    },
}
