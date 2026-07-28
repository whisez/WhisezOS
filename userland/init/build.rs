use std::{env, error::Error, fs, fs::File, io::BufReader, path::PathBuf};

const WALLPAPER_WIDTH: usize = 1280;
const WALLPAPER_HEIGHT: usize = 752;

fn main() {
    // Same trap as the kernel's: cargo does not know the linker script is an
    // input, so editing `init.ld` leaves the previous binary in place and the
    // next boot fails against the old layout — which looks exactly like the
    // edit not working.
    println!("cargo:rerun-if-changed=init.ld");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../assets/wallpapers/whisezos-dragon.png");

    generate_wallpaper().expect("generate the embedded WhisezOS wallpaper");
}

/// Decode and crop the repository's wallpaper once on the build host. The
/// freestanding init process then only has to copy RGB bytes to the framebuffer;
/// it does not carry a PNG decoder, allocator, or filesystem dependency.
fn generate_wallpaper() -> Result<(), Box<dyn Error>> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest dir")?);
    let source = manifest.join("../../assets/wallpapers/whisezos-dragon.png");
    let output =
        PathBuf::from(env::var_os("OUT_DIR").ok_or("output dir")?).join("whisezos-dragon.rgb");

    let mut decoder = png::Decoder::new(BufReader::new(File::open(source)?));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info()?;
    let mut decoded = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or("PNG output is too large")?
    ];
    let info = reader.next_frame(&mut decoded)?;
    let pixels = &decoded[..info.buffer_size()];
    let source_width = info.width as usize;
    let source_height = info.height as usize;

    let channels = match info.color_type {
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Indexed => return Err("indexed PNG was not expanded".into()),
    };

    // Crop to the desktop's aspect ratio instead of stretching the dragon.
    let (crop_x, crop_y, crop_width, crop_height) =
        if source_width * WALLPAPER_HEIGHT > source_height * WALLPAPER_WIDTH {
            let width = source_height * WALLPAPER_WIDTH / WALLPAPER_HEIGHT;
            ((source_width - width) / 2, 0, width, source_height)
        } else {
            let height = source_width * WALLPAPER_HEIGHT / WALLPAPER_WIDTH;
            (0, (source_height - height) / 2, source_width, height)
        };

    let mut rgb = Vec::with_capacity(WALLPAPER_WIDTH * WALLPAPER_HEIGHT * 3);
    for y in 0..WALLPAPER_HEIGHT {
        let source_y = crop_y + y * crop_height / WALLPAPER_HEIGHT;
        for x in 0..WALLPAPER_WIDTH {
            let source_x = crop_x + x * crop_width / WALLPAPER_WIDTH;
            let at = (source_y * source_width + source_x) * channels;
            match info.color_type {
                png::ColorType::Rgb | png::ColorType::Rgba => {
                    rgb.extend_from_slice(&pixels[at..at + 3]);
                }
                png::ColorType::Grayscale | png::ColorType::GrayscaleAlpha => {
                    rgb.extend_from_slice(&[pixels[at], pixels[at], pixels[at]]);
                }
                png::ColorType::Indexed => unreachable!(),
            }
        }
    }

    fs::write(output, rgb)?;
    Ok(())
}
