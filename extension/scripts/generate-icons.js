/**
 * Generate PNG icons from inline canvas drawing.
 * Uses node-canvas-like approach — but since we may not have node-canvas,
 * we'll create minimal valid PNG files directly.
 */

const fs = require('fs');
const path = require('path');

// Minimal PNG generator for solid-colour icons with a shield shape
// This creates small, valid PNG files

function createPNG(width, height) {
  // We'll write a minimal uncompressed PNG
  const { deflateSync } = require('zlib');

  // Image data (RGBA)
  const pixels = Buffer.alloc(width * height * 4, 0);

  const cx = width / 2;
  const cy = height / 2;
  const r  = width / 2 - 1;

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (y * width + x) * 4;
      const dx = x - cx;
      const dy = y - cy;
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (dist <= r) {
        // Gradient from #6C5CE7 to #A29BFE
        const t = (x + y) / (width + height);
        const r1 = Math.round(108 + (162 - 108) * t);
        const g1 = Math.round(92  + (155 - 92)  * t);
        const b1 = Math.round(231 + (254 - 231) * t);

        // Shield shape check
        const nx = (x - cx) / r; // normalized -1 to 1
        const ny = (y - cy) / r;

        // Shield: top straight edge, sides narrow toward bottom
        const shieldTop = -0.65;
        const shieldBot = 0.75;
        const inShield = ny >= shieldTop && ny <= shieldBot &&
                         Math.abs(nx) <= (ny < 0 ? 0.55 : 0.55 - 0.55 * Math.pow(ny / shieldBot, 1.5));

        if (inShield) {
          // White shield
          pixels[idx]     = 255;
          pixels[idx + 1] = 255;
          pixels[idx + 2] = 255;
          pixels[idx + 3] = 240;

          // Inner shield (purple again, smaller)
          const innerScale = 0.72;
          const inx = nx / innerScale;
          const iny = (ny - 0.02) / innerScale;

          const innerShieldTop = -0.65;
          const innerShieldBot = 0.75;
          const inInner = iny >= innerShieldTop && iny <= innerShieldBot &&
                          Math.abs(inx) <= (iny < 0 ? 0.55 : 0.55 - 0.55 * Math.pow(iny / innerShieldBot, 1.5));

          if (inInner) {
            pixels[idx]     = r1;
            pixels[idx + 1] = g1;
            pixels[idx + 2] = b1;
            pixels[idx + 3] = 220;

            // Checkmark (rough line drawing)
            // Check goes from roughly (-0.3, 0) to (-0.05, 0.25) to (0.35, -0.25)
            const checkDist = distToLineSegments(nx, ny, [
              { x1: -0.22, y1: 0.0, x2: -0.05, y2: 0.18 },
              { x1: -0.05, y1: 0.18, x2: 0.28, y2: -0.18 },
            ]);
            const strokeW = 0.055;
            if (checkDist < strokeW) {
              pixels[idx]     = 255;
              pixels[idx + 1] = 255;
              pixels[idx + 2] = 255;
              pixels[idx + 3] = 255;
            }
          }
        } else {
          // Circle background
          pixels[idx]     = r1;
          pixels[idx + 1] = g1;
          pixels[idx + 2] = b1;
          pixels[idx + 3] = 255;
        }
      }
      // else transparent (0,0,0,0)
    }
  }

  // Build PNG
  // Signature
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // colour type (RGBA)
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // Raw image data with filter bytes
  const rawRows = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 4);
    row[0] = 0; // no filter
    pixels.copy(row, 1, y * width * 4, (y + 1) * width * 4);
    rawRows.push(row);
  }
  const rawData = Buffer.concat(rawRows);
  const compressed = deflateSync(rawData);

  // Build chunks
  function makeChunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeB = Buffer.from(type, 'ascii');
    const combined = Buffer.concat([typeB, data]);
    const crc = crc32(combined);
    const crcB = Buffer.alloc(4);
    crcB.writeUInt32BE(crc >>> 0, 0);
    return Buffer.concat([len, combined, crcB]);
  }

  const ihdrChunk = makeChunk('IHDR', ihdr);
  const idatChunk = makeChunk('IDAT', compressed);
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([sig, ihdrChunk, idatChunk, iendChunk]);
}

function distToLineSegments(px, py, segments) {
  let minDist = Infinity;
  for (const { x1, y1, x2, y2 } of segments) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const lenSq = dx * dx + dy * dy;
    let t = lenSq > 0 ? ((px - x1) * dx + (py - y1) * dy) / lenSq : 0;
    t = Math.max(0, Math.min(1, t));
    const closestX = x1 + t * dx;
    const closestY = y1 + t * dy;
    const d = Math.sqrt((px - closestX) ** 2 + (py - closestY) ** 2);
    minDist = Math.min(minDist, d);
  }
  return minDist;
}

// CRC32
function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c;
    }
  }
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// Generate icons
const sizes = [16, 48, 128];
const outDir = path.join(__dirname, '..');

for (const size of sizes) {
  const png = createPNG(size, size);
  const filePath = path.join(outDir, 'icons', `icon${size}.png`);
  fs.writeFileSync(filePath, png);
  console.log(`Created ${filePath} (${png.length} bytes)`);
}

console.log('Done!');
