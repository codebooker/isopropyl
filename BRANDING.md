# ISOpropyl brand assets

ISOpropyl's visual identity combines a silver image disk with an amber droplet.
The disk communicates boot media, the curved amber stroke suggests a write in
progress, and the droplet makes the ISOpropyl name memorable without borrowing
platform-specific imagery.

## Official artwork

- [`data/io.github.codebooker.isopropyl.svg`](data/io.github.codebooker.isopropyl.svg)
  is the scalable application icon and primary symbol.
- `data/icons/` contains 48, 64, 128, and 256 pixel transparent PNG exports for
  desktop environments that do not reliably load scalable application icons.
- [`data/isopropyl-hero.svg`](data/isopropyl-hero.svg) is the repository banner
  and wordmark treatment.
- [`data/screenshot.png`](data/screenshot.png) is the current README and
  AppStream product screenshot.

Use the name **ISOpropyl** with that exact capitalization in prose. The package,
executable, and repository name remain lowercase `isopropyl`.

The preferred tagline is **Bootable media, without the guesswork.** Use it for
project pages and release artwork, not as part of the application name.

## Palette

| Role | Color |
|---|---|
| Amber | `#F6922E` |
| Deep charcoal | `#0D1118` |
| Slate | `#1B2230` |
| Primary text | `#F8FAFD` |
| Secondary text | `#D0D7E2` |

Keep the symbol's proportions intact, preserve clear space around it, and do not
separate the disc from the droplet. The source SVGs are the canonical assets;
raster exports should be derived from them rather than edited independently.

## Usage

- Use the complete rounded-square icon for launchers, stores, avatars, and
  favicons. Do not remove its graphite field for those uses.
- Keep clear space around the icon equal to at least one eighth of its width.
- Prefer the 48-pixel icon or larger. At smaller sizes, render from the SVG; do
  not redraw or simplify individual elements by hand.
- Place the hero on a neutral page background with enough width to preserve its
  10:3 aspect ratio. Do not crop the symbol, wordmark, or tagline.
- Never recolor the amber path independently of the droplet, add third-party
  marks, rotate the icon, or use the droplet by itself as the project logo.

The application icon is also copied into `isopropyl/data/` so installed wheels
retain a theme-independent runtime fallback. The two SVG files must remain
byte-for-byte identical. Unless a file says otherwise, ISOpropyl's original
brand artwork is distributed under `AGPL-3.0-or-later` with the application.
