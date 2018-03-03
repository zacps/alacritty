extern crate font_loader;
use self::font_loader::system_fonts;

extern crate rusttype;
use self::rusttype::{point, Codepoint, FontCollection, Scale};

use super::{FontDesc, FontKey, GlyphKey, Metrics, RasterizedGlyph, Size, Slant, Style, Weight};

pub struct RustTypeRasterizer {
    fonts: Vec<rusttype::Font<'static>>,
    dpi: f32,
}

impl ::Rasterize for RustTypeRasterizer {
    type Err = Error;

    fn new(device_pixel_ratio: f32, _: bool) -> Result<RustTypeRasterizer, Error> {
        Ok(RustTypeRasterizer {
            fonts: Vec::new(),
            dpi: device_pixel_ratio,
        })
    }

    fn metrics(&self, key: FontKey, size: Size) -> Result<Metrics, Error> {
        let scale = Scale::uniform(size.as_f32_pts());
        info!("DPI: {}", self.dpi);
        let vmetrics = self.fonts[key.token as usize].v_metrics(scale);
        let hmetrics = self.fonts[key.token as usize]
            .glyph(
                // If the font is monospaced all glyphs *should* have the same width
                // 32 '!' is the first displaying character
                Codepoint(33),
            )
            .ok_or(Error::MissingGlyph)?
            .scaled(scale)
            .h_metrics();
        Ok(Metrics {
            descent: vmetrics.descent,
            average_advance: hmetrics.advance_width as f64,
            line_height: (vmetrics.ascent - vmetrics.descent + vmetrics.line_gap) as f64, // TODO: ?
        })
    }

    fn load_font(&mut self, desc: &FontDesc, _size: Size) -> Result<FontKey, Error> {
        let fp = system_fonts::FontPropertyBuilder::new()
            .family(&desc.name)
            .monospace();

        let fp = match desc.style {
            Style::Specific(_) => unimplemented!(""),
            Style::Description { slant, weight } => {
                let fp = match slant {
                    Slant::Normal => fp,
                    Slant::Italic => fp.italic(),
                    // This style is not supported by rust-font-loader
                    Slant::Oblique => return Err(Error::UnsupportedStyle),
                };
                match weight {
                    Weight::Bold => fp.bold(),
                    Weight::Normal => fp,
                }
            }
        };
        self.fonts.push(FontCollection::from_bytes(
            system_fonts::get(&fp.build())
                .ok_or(Error::MissingFont(desc.clone()))?
                .0,
        ).into_font()
            .ok_or(Error::UnsupportedFont)?);
        Ok(FontKey {
            token: (self.fonts.len() - 1) as u16,
        })
    }

    fn get_glyph(&mut self, glyph_key: &GlyphKey) -> Result<RasterizedGlyph, Error> {
        let scaled_glyph = self.fonts[glyph_key.font_key.token as usize]
            .glyph(glyph_key.c)
            .ok_or(Error::MissingGlyph)?
            .scaled(Scale::uniform(glyph_key.size.as_f32_pts()));

        // TODO: I think 0,0 is the origin. This should be changed by the offset specified in alacritty.yml
        // font.glyph_offset.x,y
        let glyph = scaled_glyph.positioned(point(0.0, 0.0));

        // Pixel bounding box
        let bb = match glyph.pixel_bounding_box() {
            Some(bb) => bb,
            // NOTE: Bounding box calculation fails for spaces
            None => rusttype::Rect {
                min: point(0, 0),
                max: point(0, 0),
            },
        };

        let mut buf = Vec::with_capacity((bb.width() * bb.height()) as usize);

        let mut counter = 0;
        glyph.draw(|_x, _y, v| {
            counter += 1;
            buf.push((v * 255.0) as u8);
            buf.push((v * 255.0) as u8);
            buf.push((v * 255.0) as u8);
        });
        // NOTE: These conversions may reduce accuracy
        Ok(RasterizedGlyph {
            c: glyph_key.c,
            width: bb.width(),
            height: bb.height(),
            top: -bb.min.y,
            left: bb.min.x,
            buf: buf,
        })
    }
}

#[derive(Debug)]
pub enum Error {
    MissingFont(FontDesc),
    UnsupportedFont,
    UnsupportedStyle,
    // NOTE: This error is different from how the FreeType code handles it
    MissingGlyph,
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::MissingFont(ref _desc) => "couldn't find the requested font",
            Error::UnsupportedFont => "only TrueType fonts are supported",
            Error::UnsupportedStyle => "the selected style is not supported by rusttype",
            Error::MissingGlyph => "the selected font did not have the requested glyph",
        }
    }
}

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        // TODO Improve error messages
        match *self {
            Error::MissingFont(ref desc) => write!(
                f,
                "Couldn't find a font with {}\
                 \n\tPlease check the font config in your alacritty.yml.",
                desc
            ),
            Error::UnsupportedFont => write!(
                f,
                "Rusttype only supports TrueType fonts.\n\tPlease select a TrueType font instead."
            ),
            Error::UnsupportedStyle => {
                write!(f, "The selected font style is not supported by rusttype.")
            }
            Error::MissingGlyph => write!(f, "The selected font did not have the requested glyph."),
        }
    }
}