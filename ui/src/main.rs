#![windows_subsystem = "windows"]

use cert_tools::{Chain, PrivateKey};
use iced::widget::text_editor::{default, Content, Status};
use iced::widget::{
    button, column, container, horizontal_rule, horizontal_space, row, text, text_editor,
    Container, Scrollable,
};
use iced::{application, clipboard, Background, Color, Element, Font, Length, Size, Task};
use itertools::Itertools;
use std::cmp::Ordering;
use std::path::PathBuf;
use std::time::SystemTime;

fn main() -> iced::Result {
    application(Ui::title, Ui::update, Ui::view)
        .resizable(false)
        .window_size(Size::new(1024.0, 800.0))
        .scale_factor(|_| 0.8)
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
    output: Content,
    status: String,
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
                output: Content::default(),
                status: String::new(),
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
                self.chain = match self.load_chain() {
                    Ok(chain) => Some(chain),
                    _ => None,
                };
                self.update(Message::Print)
            }
            Message::ClearCaFile => {
                self.ca_file = File::None;
                self.chain = match self.load_chain() {
                    Ok(chain) => Some(chain),
                    _ => None,
                };
                self.update(Message::Print)
            }
            Message::ClearKeyFile => {
                self.key_file = File::None;
                self.chain = match self.load_chain() {
                    Ok(chain) => Some(chain),
                    _ => None,
                };
                self.update(Message::Print)
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
                        self.output = Content::default();
                        self.mode = UiMode::CertList;
                    }
                    _ => self.cert_file = File::None,
                };
                self.update(Message::Print)
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
                        self.output = Content::default();
                    }
                    _ => self.ca_file = File::None,
                };
                self.update(Message::Print)
            }
            Message::SetKeyFile(file) => {
                match file {
                    Ok(file) => {
                        self.key_file = match PrivateKey::read(&file) {
                            Ok(key) => File::PrivateKey(file, Box::new(key)),
                            Err(_) => File::Invalid(file),
                        };
                        self.output = Content::default();
                    }
                    _ => self.key_file = File::None,
                };
                self.update(Message::Print)
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
            Message::Merge => {
                match self.merge_output() {
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
            Message::Copy => clipboard::write::<Message>(self.output.text()),
        }
    }

    fn view(&self) -> Element<Message> {
        fn grey_style() -> text::Style {
            text::Style {
                color: Some(Color::parse("#888888").unwrap()),
            }
        }

        fn red_style() -> text::Style {
            text::Style {
                color: Some(Color::parse("#aa0000").unwrap()),
            }
        }

        let cert_file_input = {
            row![
                text("Certificate: ").width(100),
                text(match self.cert_file {
                    File::Invalid(ref file) | File::Certificates(ref file, _) =>
                        file.display().to_string(),
                    _ => "No certificate file".to_string(),
                })
                .style(|_| match self.cert_file {
                    File::Certificates(_, _) => text::Style::default(),
                    File::Invalid(_) => red_style(),
                    _ => grey_style(),
                }),
                horizontal_space(),
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
        };

        let ca_file_input = {
            row![
                text("CA: ").width(100),
                text(match self.ca_file {
                    File::Invalid(ref file) | File::Certificates(ref file, _) =>
                        file.display().to_string(),
                    _ => "No CA file".to_string(),
                })
                .style(|_| match self.ca_file {
                    File::Certificates(_, _) => text::Style::default(),
                    File::Invalid(_) => red_style(),
                    _ => grey_style(),
                }),
                horizontal_space(),
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
        };

        let key_file_input = {
            row![
                text("Key: ").width(100),
                text(match self.key_file {
                    File::Invalid(ref file) | File::PrivateKey(ref file, _) =>
                        file.display().to_string(),
                    _ => "No key file".to_string(),
                })
                .style(|_| match self.key_file {
                    File::PrivateKey(_, _) => text::Style::default(),
                    File::Invalid(_) => red_style(),
                    _ => grey_style(),
                }),
                horizontal_space(),
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
        };

        let clip_button = if self.output.text().trim().is_empty() {
            button("Copy to Clipboard").style(button::secondary)
        } else {
            button("Copy to Clipboard")
                .on_press(Message::Copy)
                .style(button::secondary)
        };
        let buttons = if self.cert_file.is_some() {
            row![
                button("Print information")
                    .on_press(Message::Print)
                    .style(button::primary),
                button("Merge into PEM")
                    .on_press(Message::Merge)
                    .style(button::primary),
                text(" "),
                clip_button,
                horizontal_space(),
            ]
        } else {
            row![
                button("Print information").style(button::primary),
                button("Merge into PEM").style(button::primary),
                text(" "),
                clip_button,
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
                for cert in chain.certs() {
                    result = result.push(
                        Container::new(column![
                            text(cert.name().to_string()).size(18),
                            horizontal_rule(1),
                            row![text("Issuer: ").width(200), text(cert.issuer().to_string())],
                            row![
                                text("Gültigkeit: ").width(200),
                                text("Gültig von "),
                                if cert.is_valid_not_before(&SystemTime::now()) {
                                    text(cert.not_before().to_string())
                                } else {
                                    text(cert.not_before().to_string())
                                        .color(Color::parse("#aa0000").unwrap())
                                },
                                text(" bis "),
                                if cert.is_valid_not_after(&SystemTime::now()) {
                                    text(cert.not_after().to_string())
                                } else {
                                    text(cert.not_after().to_string())
                                        .color(Color::parse("#aa0000").unwrap())
                                }
                            ],
                            row![
                                text("SHA-1-Fingerprint: ").width(200),
                                text(cert.fingerprint().sha1.to_string())
                            ],
                            row![
                                text("SHA-256-Fingerprint: ").width(200),
                                text(cert.fingerprint().sha256.to_string())
                            ],
                            row![
                                text("Subject-Key-Id: ").width(200),
                                text(cert.subject_key_id().to_string())
                            ],
                            row![
                                text("Authority_Key-Id: ").width(200),
                                text(cert.authority_key_id().to_string())
                            ],
                            if cert.dns_names().is_empty() {
                                row![]
                            } else {
                                row![
                                    text("DNS-Names: ").width(200),
                                    text(cert.dns_names().join(", "))
                                ]
                            },
                        ])
                            .padding(8)
                            .style(|_| container::Style {
                                background: Some(Background::Color(Color::WHITE)),
                                ..container::Style::default()
                            })
                            .width(Length::Fill),
                    )
                }
            };

            let content =
                Container::new(result.spacing(4))
                    .padding(4)
                    .style(|_| container::Style {
                        background: Some(Background::Color(Color::parse("#eeeeee").unwrap())),
                        ..container::Style::default()
                    });
            Scrollable::new(content).height(Length::Fill)
        };

        let chain_info = {
            let mut result = column![];

            result = result.push(if let Some(chain) = &self.chain {
                if chain.has_missing_tail() {
                    column![
                            Container::new(text("Last Certificate points to another one that should be contained in chain.")).style(|_| container::Style {
                            background: Some(Background::Color(Color::parse("#eeaa00").unwrap())),
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
                            background: Some(Background::Color(Color::parse("#00aa00").unwrap())),
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
                        background: Some(Background::Color(Color::parse("#aa0000").unwrap())),
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
                                background: Some(Background::Color(
                                    Color::parse("#00aa00").unwrap()
                                )),
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
                                background: Some(Background::Color(
                                    Color::parse("#aa0000").unwrap()
                                )),
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
            let content = match self.indicator_state() {
                IndicatorState::Unknown => ("?", "#aaaaaa", "#ffffff"),
                IndicatorState::Success => ("OK", "#00aa00", "#ffffff"),
                IndicatorState::Error => ("Not OK", "#aa0000", "#ffffff"),
            };

            container(
                container(text(content.0))
                    .style(|_| container::Style {
                        background: Some(Background::Color(Color::parse(content.1).unwrap())),
                        text_color: Some(Color::parse(content.2).unwrap()),
                        ..container::Style::default()
                    })
                    .center_x(80)
                    .center_y(80),
            )
            .center_x(96)
            .center_y(96)
        };

        column![
            row![
                column![cert_file_input, ca_file_input, key_file_input].spacing(2),
                indicator,
            ]
            .spacing(96),
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

    fn merge_output(&self) -> Result<String, String> {
        let mut result = String::new();
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

            certs.sort_by(|cert1, cert2| {
                if cert1.subject_key_id() == cert2.authority_key_id() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            });
            let chain = Chain::from(certs.into_iter().unique().collect::<Vec<_>>());
            if !chain.is_valid() {
                return Err("Cannot merge files to valid chain - giving up!".to_string());
            }
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

    fn indicator_state(&self) -> IndicatorState {
        let mut result = IndicatorState::Unknown;

        if let File::Certificates(_, chain) = &self.cert_file {
            result = if chain.is_valid() {
                IndicatorState::Success
            } else {
                IndicatorState::Error
            };

            if let File::Certificates(_, ca_chain) = &self.ca_file {
                let mut certs = vec![];
                for cert in chain.certs() {
                    certs.push(cert.clone());
                }
                for ca_cert in ca_chain.certs() {
                    certs.push(ca_cert.clone());
                }
                let chain = Chain::from(certs);
                result = if chain.is_valid() {
                    IndicatorState::Success
                } else {
                    IndicatorState::Error
                };
            }

            if let File::PrivateKey(_, private_key) = &self.key_file {
                if let Some(cert) = chain.certs().first() {
                    return if cert.public_key_matches(private_key) && chain.is_valid() {
                        result
                    } else {
                        IndicatorState::Error
                    };
                }
            }
        }

        result
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
    Merge,
    Copy,
}

#[derive(Debug, Clone)]
enum Error {
    Undefined,
}

enum IndicatorState {
    Unknown,
    Success,
    Error,
}

async fn pick_file() -> Result<PathBuf, Error> {
    let path = rfd::AsyncFileDialog::new()
        .set_title("Open file...")
        .pick_file()
        .await
        .ok_or(Error::Undefined)?;

    Ok(path.into())
}
