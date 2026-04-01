#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

pub mod string {
    use std::{ffi, iter, str};
    pub fn to_wide(string: &str) -> Box<[u16]> {
        use std::os::windows::ffi::OsStrExt as _;
        ffi::OsStr::new(string)
            .encode_wide()
            .chain(iter::once(0))
            .collect()
    }
}

static NAME: &str = "Anti-GPU Encrypter";
static IMAGE: Option<egui::ImageSource<'static>> = None;

fn main() -> Result<(), eframe::Error> {
    env_logger::init();
    let image = IMAGE.as_ref();
    eframe::run_native(
        NAME,
        eframe::NativeOptions {
            renderer: eframe::Renderer::Wgpu,
            viewport: App::viewport(image),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(App::new(cc, image)?))),
    )?;
    Ok(())
}

#[derive(Default)]
struct App {
    path1: String,
    path1_lock: Arc<Mutex<Option<String>>>,
    path2: String,
    path2_lock: Arc<Mutex<Option<String>>>,
    text: String,
    label: String,
    label_lock: Arc<Mutex<Option<String>>>,
    image: Option<egui::ImageSource<'static>>,
}

impl App {
    fn new(
        cc: &eframe::CreationContext,
        image: Option<&egui::ImageSource<'static>>,
    ) -> Result<Self, eframe::Error> {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        Self::font(&cc.egui_ctx);
        let size_hint = egui::SizeHint::Scale(eframe::emath::OrderedFloat(1.0));
        let mut this: Self = Default::default();
        this.image = image
            .map(|image| Self::texture(cc, image, size_hint).ok())
            .flatten();
        Ok(this)
    }

    fn viewport(image: Option<&egui::ImageSource<'static>>) -> egui::ViewportBuilder {
        let image = image.map(Self::icon).flatten().unwrap_or_default();
        <egui::ViewportBuilder as Default>::default()
            .with_inner_size([680.0, 260.0])
            .with_icon(Arc::new(image))
    }
    fn font(ctx: &egui::Context) {
        use io::Read as _;
        use winreg::{RegKey, enums as e};
        let windir = std::env::var("windir");
        let path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts";
        let keys: [io::Result<RegKey>; _] = [e::HKEY_LOCAL_MACHINE, e::HKEY_CURRENT_USER]
            .map(|key| RegKey::open_subkey(&RegKey::predef(key), path));

        let Some((id, font_data)) = keys
            .iter()
            .map(Result::as_ref)
            .filter_map(Result::ok)
            .flat_map(RegKey::enum_values)
            .filter_map(Result::ok)
            .filter_map(|(id, value)| {
                if !id.starts_with("Microsoft YaHei") {
                    return None;
                }
                let value = format!("{}", value);
                let path = Path::new(&value);
                let windir = windir.as_deref().unwrap_or(r"C:\Windows");

                let file = match path.is_relative() {
                    true => File::open(format!(r"{}\Fonts\{}", windir, value)),
                    false => File::open(&path),
                };
                let mut data: Vec<u8> = Default::default();
                file.ok()?.read_to_end(&mut data).ok()?;
                log::info!("Font: {}", id);
                Some((id, data))
            })
            .next()
        else {
            use windows::Win32::UI::WindowsAndMessaging::{MB_OK, MessageBoxW};
            use windows_core::{PWSTR, w};
            unsafe {
                let mut text = string::to_wide("找不到字体");
                let title = w!("字体");
                MessageBoxW(None, PWSTR(<[u16]>::as_mut_ptr(&mut text)), title, MB_OK);
            }
            return;
        };
        let mut fonts = <egui::FontDefinitions as Default>::default();
        fonts.font_data.insert(
            Clone::clone(&id),
            Arc::new(egui::FontData::from_owned(font_data)),
        );
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .insert(0, Clone::clone(&id));
        }
        ctx.set_fonts(fonts);
    }
    fn texture(
        cc: &eframe::CreationContext,
        image: &egui::ImageSource<'static>,
        size_hint: egui::SizeHint,
    ) -> Result<egui::ImageSource<'static>, eframe::Error> {
        Ok(egui::ImageSource::Texture(loop {
            use egui::load::TexturePoll::Ready;
            match Clone::clone(image).load(&cc.egui_ctx, Default::default(), size_hint) {
                Ok(poll) => match poll {
                    Ready { texture } => break texture,
                    _ => continue,
                },
                Err(e) => return Err(eframe::Error::AppCreation(Box::new(e))),
            }
        }))
    }
    fn icon(image: &egui::ImageSource<'static>) -> Option<egui::IconData> {
        let egui::ImageSource::Bytes { bytes, .. } = Clone::clone(image) else {
            return None;
        };
        let format = image::ImageFormat::Png;
        let img = image::load_from_memory_with_format(&bytes, format).ok()?;
        let rgba = img.into_rgba8();
        let (width, height) = (rgba.width(), rgba.height());
        let rgba: Vec<u8> = rgba.into_raw();
        Some(egui::IconData {
            rgba,
            width,
            height,
        })
    }

    fn update<'a, T>(data: &'a mut T, lock: &Mutex<Option<T>>) -> Option<&'a mut T> {
        if let Ok(mut lock) = lock.try_lock() {
            if let Some(lock) = Option::take(&mut lock) {
                *data = lock;
                return Some(data);
            }
        }
        None
    }
    fn is_lock<T>(lock: &Mutex<T>) -> bool {
        use std::sync::TryLockError;
        if let Err(TryLockError::WouldBlock) = lock.try_lock() {
            return true;
        };
        false
    }
    fn pick_file(ui: &egui::Ui, lock: &Arc<Mutex<Option<String>>>, reverse: bool) {
        use rfd::FileDialog;
        use std::ffi::OsString;
        use std::path::PathBuf;
        let ctx = Clone::clone(ui.ctx());
        let lock = Clone::clone(lock);
        let mut filter_list: [(&str, &[&str]); _] = [
            ("所有文件", &["*"]),
            ("zip 文件", &["zip"]),
            ("AGE 加密文件", &["age.zip"]),
        ];
        if reverse {
            filter_list.reverse();
        }
        thread::spawn(move || {
            let Ok(mut lock) = lock.try_lock() else {
                return;
            };
            let mut dialog = FileDialog::new();
            for (name, ext) in filter_list {
                dialog = dialog.add_filter(name, ext);
            }
            if let Some(Ok(file)) = dialog
                .pick_file()
                .map(PathBuf::into_os_string)
                .map(OsString::into_string)
            {
                *lock = Some(file);
                ctx.request_repaint();
            }
        });
    }
    fn spawn(ui: &egui::Ui, lock: &Arc<Mutex<Option<String>>>, args: &[&str]) {
        use std::process::{Command, Stdio};
        let ctx = Clone::clone(ui.ctx());
        let lock = Clone::clone(lock);

        let Ok(child) = Command::new("age")
            .args(args)
            .stderr(Stdio::piped())
            .spawn()
        else {
            if let Ok(mut lock) = lock.lock() {
                *lock = Some(String::from("启动进程失败"));
                ctx.request_repaint();
            };
            return;
        };
        thread::spawn(move || {
            let Ok(mut lock) = lock.lock() else {
                return;
            };
            let (_, data) = match child
                .wait_with_output()
                .map(|output| (output.status.code(), String::try_from(output.stderr)))
            {
                Ok((Some(status), Ok(data))) => (status, data),
                _ => (-1, String::from("未知错误")),
            };
            *lock = Some(data);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let size = [520.0, 20.0];
        <egui::CentralPanel as Default>::default().show_inside(ui, |ui| {
            ui.vertical_centered(|ui| ui.heading(NAME));
            egui::Grid::new("grid1")
                .spacing([20.0, 8.0])
                .show(ui, |ui| {
                    Self::update(&mut self.path1, &self.path1_lock).map(|path1| {
                        use std::fmt::Write as _;
                        let path2 = &mut self.path2;
                        path2.clear();
                        let _ = write!(path2, "{}.age.zip", path1);
                    });
                    ui.label("输入");
                    ui.add_sized(size, egui::TextEdit::singleline(&mut self.path1));
                    if Self::is_lock(&self.path1_lock) {
                        ui.spinner();
                    } else if ui.button("选择文件").clicked() {
                        Self::pick_file(ui, &self.path1_lock, false);
                    }
                    ui.end_row();

                    Self::update(&mut self.path2, &self.path2_lock).map(|path2| {
                        let path1 = &mut self.path1;
                        path1.clear();
                        path1.push_str(path2.trim_end_matches(".age.zip"));
                    });
                    ui.label("输出");
                    ui.add_sized(size, egui::TextEdit::singleline(&mut self.path2));
                    if Self::is_lock(&self.path2_lock) {
                        ui.spinner();
                    } else if ui.button("选择文件").clicked() {
                        Self::pick_file(ui, &self.path2_lock, true);
                    }
                    ui.end_row();

                    ui.label("密码");
                    ui.add_sized(size, egui::TextEdit::singleline(&mut self.text));
                    ui.end_row();

                    ui.label("");
                    ui.horizontal(|ui| {
                        let mut args: Option<[&str; 4]> = None;
                        if Self::is_lock(&self.label_lock) {
                            ui.spinner();
                        } else {
                            if ui.button("加密").clicked() {
                                args = Some(["e", &self.path1, &self.path2, &self.text]);
                            }
                            if ui.button("解密").clicked() {
                                args = Some(["d", &self.path2, &self.path1, &self.text]);
                            }
                        }
                        if let Some(args) = args {
                            let label = &mut self.label;
                            label.clear();
                            if args.iter().all(|x| x.len() > 0) {
                                Self::spawn(ui, &self.label_lock, &args);
                            } else {
                                use std::fmt::Write as _;
                                let _ = writeln!(label, "参数为空");
                            }
                        }
                    });
                    ui.end_row();
                });
            Self::update(&mut self.label, &self.label_lock);
            ui.label(&self.label);
            for image in [&self.image, &IMAGE] {
                if let Some(image) = image {
                    ui.image(Clone::clone(image));
                }
            }
        });
    }
}
