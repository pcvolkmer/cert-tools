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

#![windows_subsystem = "windows"]

use cert_tools::{Chain, PrivateKey};
use iced::border::Radius;
use iced::widget::text_editor::{default, Content, Status};
use iced::widget::{
    self, button, column, container, horizontal_rule, horizontal_space, row, text, text_editor,
    text_input, Container, Scrollable,
};
use iced::window::icon;
use iced::{
    alignment, application, clipboard, color, window, Background, Border, Color, Element, Font,
    Length, Pixels, Settings, Size, Task,
};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

fn main() -> iced::Result {
    application(Ui::title, Ui::update, Ui::view)
        .settings(Settings {
            default_text_size: Pixels::from(13),
            ..Settings::default()
        })
        .window(window::Settings {
            icon: match image::load_from_memory(include_bytes!("../../resources/icon.ico")) {
                Ok(image) => icon::from_rgba(image.as_bytes().to_vec(), 128, 128).ok(),
                _ => None,
            },
            ..window::Settings::default()
        })
        .resizable(false)
        .window_size(Size::new(1020.0, 800.0))
        .run_with(Ui::new)
}

enum File {
    None,
    Invalid(PathBuf),
    Certificates(PathBuf, Box<Chain>),
    PrivateKey(PathBuf, Box<PrivateKey>),
}

impl File {
    fn is_some(&self) -> bool {
        !matches!(self, Self::None)
    }
}

enum UiMode {
    CertList,
    Output,
}

struct Ui {
    cert_file: File,
    ca_file: File,
    key_file: File,

    mode: UiMode,
    chain: Option<Chain>,
    fixed_chain: Option<Chain>,
    output: Content,
    status: String,
    chain_indicator_state: IndicatorState,
    key_indicator_state: IndicatorState,
}

impl Ui {
    fn new() -> (Self, Task<Message>) {
        (
            Self {
                cert_file: File::None,
                ca_file: File::None,
                key_file: File::None,
                mode: UiMode::CertList,
                chain: None,
                fixed_chain: None,
                output: Content::default(),
                status: String::new(),
                chain_indicator_state: IndicatorState::Unknown,
                key_indicator_state: IndicatorState::Unknown,
            },
            Task::none(),
        )
    }

    fn title(&self) -> String {
        "CertTools".into()
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        self.mode = UiMode::CertList;
        match message {
            Message::PickCertFile => Task::perform(pick_file(), Message::SetCertFile),
            Message::PickCaFile => Task::perform(pick_file(), Message::SetCaFile),
            Message::PickKeyFile => Task::perform(pick_file(), Message::SetKeyFile),
            Message::ClearCertFile => {
                self.cert_file = File::None;
                self.ca_file = File::None;
                self.key_file = File::None;
                self.chain = None;
                self.fixed_chain = None;
                self.chain_indicator_state = IndicatorState::Unknown;
                self.key_indicator_state = IndicatorState::Unknown;
                Task::done(Message::Print)
            }
            Message::ClearCaFile => {
                self.ca_file = File::None;
                self.chain = match self.load_chain() {
                    Ok(chain) => Some(chain),
                    _ => None,
                };
                self.fixed_chain = match &self.chain {
                    Some(chain) => match Chain::create_fixed(chain.certs()) {
                        Ok(chain) => Some(chain),
                        _ => None,
                    },
                    _ => None,
                };
                self.chain_indicator_state = self.chain_indicator_state();
                Task::done(Message::Print)
            }
            Message::ClearKeyFile => {
                self.key_file = File::None;
                self.key_indicator_state = IndicatorState::Unknown;
                Task::done(Message::Print)
            }
            Message::SetCertFile(file) => {
                match file {
                    Ok(file) => {
                        self.cert_file = match Chain::read(&file) {
                            Ok(chain) => File::Certificates(file, Box::new(chain)),
                            Err(_) => File::Invalid(file),
                        };
                        self.chain = match self.load_chain() {
                            Ok(chain) => Some(chain),
                            _ => None,
                        };
                        self.fixed_chain = match &self.chain {
                            Some(chain) => match Chain::create_fixed(chain.certs()) {
                                Ok(chain) => Some(chain),
                                _ => None,
                            },
                            _ => None,
                        };
                        self.output = Content::default();
                        self.mode = UiMode::CertList;
                    }
                    _ => self.cert_file = File::None,
                };
                self.chain_indicator_state = self.chain_indicator_state();
                Task::done(Message::Print)
            }
            Message::SetCaFile(file) => {
                match file {
                    Ok(file) => {
                        self.ca_file = match Chain::read(&file) {
                            Ok(chain) => File::Certificates(file, Box::new(chain)),
                            Err(_) => File::Invalid(file),
                        };
                        self.chain = match self.load_chain() {
                            Ok(chain) => Some(chain),
                            _ => None,
                        };
                        self.fixed_chain = match &self.chain {
                            Some(chain) => match Chain::create_fixed(chain.certs()) {
                                Ok(chain) => Some(chain),
                                _ => None,
                            },
                            _ => None,
                        };
                        self.output = Content::default();
                    }
                    _ => self.ca_file = File::None,
                };
                self.chain_indicator_state = self.chain_indicator_state();
                Task::done(Message::Print)
            }
            Message::SetKeyFile(file) => {
                match file {
                    Ok(file) => {
                        self.key_file = match PrivateKey::read(&file) {
                            Ok(key) => File::PrivateKey(file, Box::new(key)),
                            Err(_) => File::Invalid(file),
                        };
                    }
                    _ => self.key_file = File::None,
                };
                self.key_indicator_state = self.key_indicator_state();
                Task::done(Message::Print)
            }
            Message::Print => {
                match self.print_output() {
                    Ok(output) => {
                        self.output = Content::with_text(output.as_str());
                        self.status = String::new();
                        self.mode = UiMode::CertList;
                    }
                    Err(err) => {
                        self.output = Content::default();
                        self.status = err
                    }
                };
                Task::none()
            }
            Message::PrintPem => {
                match self.pem_output() {
                    Ok(output) => {
                        self.output = Content::with_text(output.as_str());
                        self.status = String::new();
                        self.mode = UiMode::Output;
                    }
                    Err(err) => {
                        self.output = Content::default();
                        self.status = err
                    }
                };
                Task::none()
            }
            Message::CopyValue(value) => clipboard::write::<Message>(value),
            Message::Cleanup => {
                if let Some(chain) = self.fixed_chain.take() {
                    self.chain = Some(chain);
                    self.mode = UiMode::CertList;
                }
                self.chain_indicator_state = IndicatorState::Cleaned;
                Task::none()
            }
            Message::PickExportFile => Task::perform(export_file(), Message::ExportToFile),
            Message::ExportToFile(file) => {
                match file {
                    Ok(file) => match self.pem_output() {
                        Ok(output) => match fs::write(&file, output) {
                            Ok(_) => self.status = format!("Exported to {}", file.display()),
                            Err(err) => self.status = format!("{:?}", err),
                        },
                        Err(err) => self.status = err,
                    },
                    Err(err) => {
                        self.status = format!("{:?}", err);
                    }
                }
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        fn filename_text<'a>(
            placeholder: &'a str,
            file: &'a File,
        ) -> text_input::TextInput<'a, Message> {
            let text = match file {
                File::Invalid(ref file)
                | File::Certificates(ref file, _)
                | File::PrivateKey(ref file, _) => file.display().to_string(),
                _ => String::new(),
            };

            match file {
                File::Certificates(_, _) | File::PrivateKey(_, _) => text_input(placeholder, &text),
                File::Invalid(_) => text_input(placeholder, &text),
                _ => text_input(placeholder, &text),
            }
            .width(Length::Fill)
            .style(move |theme, status| text_input::Style {
                background: Background::Color(Color::WHITE),
                placeholder: color!(0x888888),
                value: match file {
                    File::Certificates(_, _) | File::PrivateKey(_, _) => Color::BLACK,
                    File::Invalid(_) => color!(0xaa0000),
                    File::None => color!(0x888888),
                },
                ..text_input::default(theme, status)
            })
        }

        let cert_file_input = {
            row![
                text("Certificate: ").width(100),
                filename_text("No certificate file", &self.cert_file),
                if self.cert_file.is_some() {
                    button("x")
                        .on_press(Message::ClearCertFile)
                        .style(button::danger)
                } else {
                    button("x").style(button::danger)
                },
                button("..")
                    .on_press(Message::PickCertFile)
                    .style(button::secondary)
            ]
            .spacing(2)
            .align_y(alignment::Vertical::Center)
        };

        let ca_file_input = {
            row![
                text("CA: ").width(100),
                filename_text("No CA file", &self.ca_file),
                if self.ca_file.is_some() {
                    button("x")
                        .on_press(Message::ClearCaFile)
                        .style(button::danger)
                } else {
                    button("x").style(button::danger)
                },
                if self.cert_file.is_some() {
                    button("..")
                        .on_press(Message::PickCaFile)
                        .style(button::secondary)
                } else {
                    button("..").style(button::secondary)
                }
            ]
            .spacing(2)
            .align_y(alignment::Vertical::Center)
        };

        let key_file_input = {
            row![
                text("Key: ").width(100),
                filename_text("No key file", &self.key_file),
                if self.key_file.is_some() {
                    button("x")
                        .on_press(Message::ClearKeyFile)
                        .style(button::danger)
                } else {
                    button("x").style(button::danger)
                },
                if self.cert_file.is_some() {
                    button("..")
                        .on_press(Message::PickKeyFile)
                        .style(button::secondary)
                } else {
                    button("..").style(button::secondary)
                }
            ]
            .spacing(2)
            .align_y(alignment::Vertical::Center)
        };

        let export_button = if !(self.chain_indicator_state == IndicatorState::Success
            || self.chain_indicator_state == IndicatorState::Cleaned)
        {
            button("Export PEM").style(button::primary)
        } else {
            button("Export PEM")
                .on_press(Message::PickExportFile)
                .style(button::primary)
        };
        let clip_button = if self.output.text().trim().is_empty() {
            button("Copy to Clipboard").style(button::secondary)
        } else {
            button("Copy to Clipboard")
                .on_press(Message::CopyValue(self.output.text().trim().to_string()))
                .style(button::secondary)
        };
        let cleanup_button = if self.fixed_chain.is_none()
            || self.chain_indicator_state == IndicatorState::Success
        {
            button("Cleanup").style(button::secondary)
        } else {
            button("Cleanup")
                .on_press(Message::Cleanup)
                .style(button::secondary)
        };
        let buttons = if self.cert_file.is_some() {
            row![
                button("Print information")
                    .on_press(Message::Print)
                    .style(button::primary),
                button("Print PEM")
                    .on_press(Message::PrintPem)
                    .style(button::primary),
                export_button,
                text(" "),
                clip_button,
                cleanup_button,
                horizontal_space(),
            ]
        } else {
            row![
                button("Print information").style(button::primary),
                button("Print PEM").style(button::primary),
                export_button,
                text(" "),
                clip_button,
                cleanup_button,
                horizontal_space(),
            ]
        }
        .spacing(2);

        let output = {
            Scrollable::new(
                text_editor(&self.output)
                    .style(|theme, _| text_editor::Style {
                        background: Background::Color(Color::BLACK),
                        value: Color::WHITE,
                        ..default(theme, Status::Disabled)
                    })
                    .font(Font::MONOSPACE),
            )
            .height(Length::Fill)
        };

        let certs = {
            let mut result = column![];

            if let Some(chain) = &self.chain {
                fn monospace_text<'a>(s: String) -> widget::Text<'a> {
                    text(s)
                        .shaping(text::Shaping::Advanced)
                        .font(Font::MONOSPACE)
                        .size(12)
                }

                for cert in chain.certs() {
                    result = result.push(
                        Container::new(
                            column![
                                text(cert.name().to_string()).size(18),
                                horizontal_rule(1),
                                row![text("Issuer: ").width(160), text(cert.issuer().to_string())],
                                row![
                                    text("Gültigkeit: ").width(160),
                                    text("Gültig von "),
                                    if cert.is_valid_not_before(&SystemTime::now()) {
                                        text(cert.not_before().to_string())
                                    } else {
                                        text(cert.not_before().to_string()).color(color!(0xaa0000))
                                    },
                                    text(" bis "),
                                    if cert.is_valid_not_after(&SystemTime::now()) {
                                        text(cert.not_after().to_string())
                                    } else {
                                        text(cert.not_after().to_string()).color(color!(0xaa0000))
                                    }
                                ],
                                row![
                                    text("SHA-1-Fingerprint: ").width(160),
                                    monospace_text(cert.fingerprint().sha1.to_string()),
                                    horizontal_space(),
                                    button("Copy to Clipboard")
                                        .style(button::secondary)
                                        .padding(1)
                                        .on_press(Message::CopyValue(
                                            cert.fingerprint().sha1.to_string()
                                        )),
                                ]
                                .align_y(alignment::Vertical::Center),
                                row![
                                    text("SHA-256-Fingerprint: ").width(160),
                                    monospace_text(cert.fingerprint().sha256.to_string()),
                                    horizontal_space(),
                                    button("Copy to Clipboard")
                                        .style(button::secondary)
                                        .padding(1)
                                        .on_press(Message::CopyValue(
                                            cert.fingerprint().sha1.to_string()
                                        )),
                                ]
                                .align_y(alignment::Vertical::Center),
                                row![
                                    text("Subject-Key-Id: ").width(160),
                                    monospace_text(cert.subject_key_id().to_string())
                                ],
                                row![
                                    text("Authority-Key-Id: ").width(160),
                                    monospace_text(cert.authority_key_id().to_string())
                                ],
                                if cert.dns_names().is_empty() {
                                    row![]
                                } else {
                                    row![
                                        text("DNS-Names: ").width(160),
                                        text(cert.dns_names().join(", "))
                                    ]
                                },
                            ]
                            .spacing(2),
                        )
                        .padding(8)
                        .style(|_| container::Style {
                            background: Some(Background::Color(Color::WHITE)),
                            ..container::Style::default()
                        })
                        .width(Length::Fill),
                    )
                }
            };

            let content = Container::new(result.spacing(4))
                .padding(4)
                .style(|_| container::Style {
                    background: Some(Background::Color(color!(0xeeeeee))),
                    ..container::Style::default()
                })
                .width(Length::Fill);
            Scrollable::new(content).height(Length::Fill)
        };

        let chain_info = {
            let mut result = column![];

            result = result.push(if let Some(chain) = &self.chain {
                if chain.has_missing_tail() {
                    column![
                            Container::new(text("Last Certificate points to another one that should be contained in chain.")).style(|_| container::Style {
                            background: Some(Background::Color(color!(0xeeaa00))),
                            text_color: Some(Color::WHITE),
                            ..container::Style::default()
                        }).padding(2).width(Length::Fill),
                            Container::new(text("Self signed (CA-) Certificate? It might be required to import a self signed Root-CA manually for applications to use it."))
                            .padding(2)
                        ]
                } else {
                    column![]
                }
            } else {
                column![]
            });

            result = result.push(if let Some(chain) = &self.chain {
                if chain.is_valid() {
                    column![Container::new(text("Chain is valid"))
                        .style(|_| container::Style {
                            background: Some(Background::Color(color!(0x00aa00))),
                            text_color: Some(Color::WHITE),
                            ..container::Style::default()
                        })
                        .padding(2)
                        .width(Length::Fill)]
                } else if !chain.certs().is_empty() {
                    column![Container::new(text(
                        "Chain or some of its parts is not valid (anymore)"
                    ))
                    .style(|_| container::Style {
                        background: Some(Background::Color(color!(0xaa0000))),
                        text_color: Some(Color::WHITE),
                        ..container::Style::default()
                    })
                    .padding(2)
                    .width(Length::Fill)]
                } else {
                    column![]
                }
            } else {
                column![]
            });

            result = result.push(if let File::PrivateKey(_, private_key) = &self.key_file {
                if let Some(chain) = &self.chain {
                    if let Some(first) = chain.certs().first() {
                        if first.public_key_matches(private_key) {
                            column![Container::new(text(
                                "Private Key matches first Cert Public Key"
                            ))
                            .style(|_| container::Style {
                                background: Some(Background::Color(color!(0x00aa00))),
                                text_color: Some(Color::WHITE),
                                ..container::Style::default()
                            })
                            .padding(2)
                            .width(Length::Fill)]
                        } else {
                            column![Container::new(text(
                                "Private Key does not match the first Cert Public Key"
                            ))
                            .style(|_| container::Style {
                                background: Some(Background::Color(color!(0xaa0000))),
                                text_color: Some(Color::WHITE),
                                ..container::Style::default()
                            })
                            .padding(2)
                            .width(Length::Fill)]
                        }
                    } else {
                        column![]
                    }
                } else {
                    column![]
                }
            } else {
                column![]
            });

            result
        };

        let indicator = {
            let chain_content = match self.chain_indicator_state {
                IndicatorState::Unknown => ("No Chain", color!(0xaaaaaa, 0.2), color!(0xaaaaaa)),
                IndicatorState::Success => ("Chain OK", color!(0x00aa00, 0.2), color!(0x00aa00)),
                IndicatorState::Error => ("Chain not OK", color!(0xaa0000, 0.2), color!(0xaa0000)),
                IndicatorState::Cleaned => {
                    ("Chain cleaned", color!(0x00aa88, 0.2), color!(0x00aa88))
                }
            };

            let key_content = match self.key_indicator_state {
                IndicatorState::Success => ("Key OK", color!(0x00aa00, 0.2), color!(0x00aa00)),
                IndicatorState::Error => ("Key not OK", color!(0xaa0000, 0.2), color!(0xaa0000)),
                _ => ("No Key", color!(0xaaaaaa, 0.2), color!(0xaaaaaa)),
            };

            container(
                column![
                    container(text(chain_content.0))
                        .style(move |_| container::Style {
                            background: Some(Background::Color(chain_content.1)),
                            text_color: Some(chain_content.2),
                            border: Border {
                                color: chain_content.2,
                                width: 1.0,
                                radius: Radius::from(4)
                            },
                            ..container::Style::default()
                        })
                        .center_x(160)
                        .center_y(40),
                    container(text(key_content.0))
                        .style(move |_| container::Style {
                            background: Some(Background::Color(key_content.1)),
                            text_color: Some(key_content.2),
                            border: Border {
                                color: key_content.2,
                                width: 1.0,
                                radius: Radius::from(4)
                            },
                            ..container::Style::default()
                        })
                        .center_x(160)
                        .center_y(40),
                ]
                .spacing(4),
            )
            .center_x(160)
            .center_y(80)
        };

        column![
            row![
                container(column![cert_file_input, ca_file_input, key_file_input].spacing(2))
                    .center_y(96),
                indicator.center_y(96),
            ]
            .spacing(40),
            horizontal_rule(1),
            buttons,
            horizontal_rule(1),
            match self.mode {
                UiMode::CertList => column![certs, chain_info],
                UiMode::Output => column![output],
            },
            horizontal_rule(1),
            text(&self.status)
        ]
        .padding(4)
        .spacing(2)
        .into()
    }

    fn print_output(&self) -> Result<String, String> {
        let mut output = vec![];
        if let File::Certificates(_, chain) = &self.cert_file {
            let mut certs = vec![];
            for cert in chain.certs() {
                certs.push(cert);
            }

            if let File::Certificates(_, ca_chain) = &self.ca_file {
                for ca_cert in ca_chain.certs() {
                    certs.push(ca_cert);
                }
            }

            for cert in chain.certs() {
                let s = format!(
                    "Name:                {}
Issuer:              {}
Gültigkeit:          Gültig von: {} bis: {}
SHA-1-Fingerprint:   {}
SHA-256-Fingerprint: {}
Subject-Key-Id:      {}
Authority-Key-Id:    {}
{}",
                    cert.name(),
                    cert.issuer(),
                    cert.not_before(),
                    cert.not_after(),
                    cert.fingerprint().sha1,
                    cert.fingerprint().sha256,
                    cert.subject_key_id(),
                    cert.authority_key_id(),
                    if cert.dns_names().is_empty() {
                        "\n".to_string()
                    } else {
                        format!("DNS-Names:           {}\n", cert.dns_names().join(", "))
                    }
                );
                output.push(s);
            }

            if chain.has_missing_tail() {
                output.push(
                    "! Last Certificate points to another one that should be contained in chain."
                        .to_string(),
                );
                output.push("  Self signed (CA-) Certificate? It might be required to import a self signed Root-CA manually for applications to use it.".to_string());
            }

            if chain.is_valid() {
                output.push("✓ Chain is valid".to_string());
            } else {
                output.push("! Chain or some of its parts is not valid (anymore)".to_string());
            }

            if let File::PrivateKey(_, private_key) = &self.key_file {
                if let Some(cert) = chain.certs().first() {
                    if cert.public_key_matches(private_key) {
                        output.push("✓ Private Key matches first Cert Public Key".to_string());
                    } else {
                        output.push(
                            "! Private Key does not match the first Cert Public Key".to_string(),
                        );
                    }
                }
            }
        }

        Ok(output.join("\n"))
    }

    fn pem_output(&self) -> Result<String, String> {
        let mut result = String::new();
        let chain = self.chain.as_ref();
        if let Some(chain) = chain {
            for cert in chain.certs() {
                match cert.to_pem() {
                    Ok(plain) => result.push_str(&plain),
                    Err(_) => {
                        return Err("Cannot merge files to valid chain - Cert error!".to_string());
                    }
                }
            }
        }
        Ok(result)
    }

    fn load_chain(&self) -> Result<Chain, String> {
        if let File::Certificates(_, chain) = &self.cert_file {
            let mut certs = vec![];
            for cert in chain.certs() {
                certs.push(cert.clone());
            }

            if let File::Certificates(_, ca_chain) = &self.ca_file {
                for ca_cert in ca_chain.certs() {
                    certs.push(ca_cert.clone());
                }
            }
            return Ok(Chain::from(certs));
        }
        Ok(Chain::from(vec![]))
    }

    fn chain_indicator_state(&self) -> IndicatorState {
        if let Some(chain) = &self.chain {
            if chain.is_valid() {
                IndicatorState::Success
            } else {
                IndicatorState::Error
            }
        } else {
            IndicatorState::Unknown
        }
    }

    fn key_indicator_state(&self) -> IndicatorState {
        if let Some(chain) = &self.chain {
            if let File::PrivateKey(_, private_key) = &self.key_file {
                if let Some(cert) = chain.certs().first() {
                    return if cert.public_key_matches(private_key) {
                        IndicatorState::Success
                    } else {
                        IndicatorState::Error
                    };
                }
            }
        }
        IndicatorState::Unknown
    }
}

#[derive(Debug, Clone)]
enum Message {
    PickCertFile,
    PickCaFile,
    PickKeyFile,
    ClearCertFile,
    ClearCaFile,
    ClearKeyFile,
    SetCertFile(Result<PathBuf, Error>),
    SetCaFile(Result<PathBuf, Error>),
    SetKeyFile(Result<PathBuf, Error>),
    Print,
    PrintPem,
    CopyValue(String),
    Cleanup,
    PickExportFile,
    ExportToFile(Result<PathBuf, Error>),
}

#[derive(Debug, Clone)]
enum Error {
    Undefined,
}

#[derive(PartialEq)]
enum IndicatorState {
    Unknown,
    Success,
    Error,
    Cleaned,
}

async fn pick_file() -> Result<PathBuf, Error> {
    let path = rfd::AsyncFileDialog::new()
        .set_title("Open file...")
        .pick_file()
        .await
        .ok_or(Error::Undefined)?;

    Ok(path.into())
}

async fn export_file() -> Result<PathBuf, Error> {
    let path = rfd::AsyncFileDialog::new()
        .set_title("Export file...")
        .add_filter("PEM-File", &["crt", "pem"])
        .save_file()
        .await
        .ok_or(Error::Undefined)?;

    Ok(path.into())
}
