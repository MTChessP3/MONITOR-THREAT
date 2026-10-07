// Executive OSINT — Reverse Image Search con deteccion facial real (face-api.js)
//
// Recibe una imagen (base64 o multipart) y:
//  1. Sube la imagen a tmpfiles.org (hosting publico gratuito)
//  2. Detecta el rostro en la imagen original con face-api.js (SSD MobileNet)
//     y extrae su descriptor de 128 dimensiones (face embedding)
//  3. Ejecuta Bing Visual Search para obtener candidatos
//  4. Para cada candidato: descargar imagen, detectar rostro, extraer descriptor,
//     y comparar con el descriptor original usando distancia euclidiana
//  5. Mantiene los que tienen distancia < threshold (mismo rostro)
//  6. Si no se detecta rostro en la original, fallback a histograma de color
//     (encuentra imagenes con paleta similar)
//  7. Genera URLs de reverse image search para Google/Yandex/Edge/DuckDuckGo/TinEye

import { NextResponse } from "next/server";
import { writeFile, mkdir } from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import sharp from "sharp";

// Polyfill TextEncoder/TextDecoder BEFORE requiring face-api (Next.js/Turbopack issue)
// face-api uses `this.util.TextEncoder` internally during require() — needs polyfill
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _g: any = globalThis as any;
if (typeof _g.TextEncoder === "undefined") _g.TextEncoder = require("util").TextEncoder;
if (typeof _g.TextDecoder === "undefined") _g.TextDecoder = require("util").TextDecoder;

// Load face-api eagerly via require() — dynamic import() fails under Turbopack
let _faceapi: any = null;
let _tf: any = null;
let _modelsLoaded = false;
let _faceApiInitFailed = false;

try {
  _faceapi = require("@vladmandic/face-api");
  _tf = require("@tensorflow/tfjs");
} catch (err) {
  console.error("[image-search] face-api load failed at boot:", err);
  _faceApiInitFailed = true;
}

async function initFaceApi(): Promise<boolean> {
  if (_faceApiInitFailed || !_faceapi || !_tf) return false;
  try {
    await _tf.setBackend("cpu");
    await _tf.ready();
    if (!_modelsLoaded) {
      const modelPath = path.join(process.cwd(), "node_modules/@vladmandic/face-api/model");
      if (existsSync(modelPath)) {
        await _faceapi.nets.ssdMobilenetv1.loadFromDisk(modelPath);
        await _faceapi.nets.faceLandmark68Net.loadFromDisk(modelPath);
        await _faceapi.nets.faceRecognitionNet.loadFromDisk(modelPath);
        _modelsLoaded = true;
      }
    }
    return _modelsLoaded;
  } catch (err) {
    console.error("[image-search] face-api init failed:", err);
    _faceApiInitFailed = true;
    return false;
  }
}

interface ImageMatch {
  url: string;          // page URL where image appears (purl)
  imageUrl: string;      // direct image URL (murl)
  thumbnailUrl: string;  // thumbnail (turl)
  title: string;
  source: string;
  width?: number;
  height?: number;
  distance: number;      // euclidean distance (face) or 0 (color match)
  similarity: number;    // 0-100 percentage
  matchType: "face" | "color" | "exact";
}

function htmlFetchHeaders(): Record<string, string> {
  return {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip",
  };
}

// ============================================================
//  Perceptual hash (fallback cuando no hay rostro)
// ============================================================
async function computePHash(buffer: Buffer): Promise<string> {
  const { data } = await sharp(buffer)
    .resize(32, 32, { fit: "fill" })
    .grayscale()
    .raw()
    .toBuffer({ resolveWithObject: true });
  let sum = 0;
  for (let i = 0; i < data.length; i++) sum += data[i];
  const avg = sum / data.length;
  let hash = "";
  for (let i = 0; i < data.length; i++) hash += data[i] > avg ? "1" : "0";
  return hash;
}

function hammingDistance(h1: string, h2: string): number {
  let dist = 0;
  const len = Math.min(h1.length, h2.length);
  for (let i = 0; i < len; i++) if (h1[i] !== h2[i]) dist++;
  return dist + Math.abs(h1.length - h2.length);
}

// ============================================================
//  Color histogram (fallback cuando no hay rostro)
// ============================================================
async function computeColorHistogram(buffer: Buffer): Promise<number[]> {
  const { data } = await sharp(buffer)
    .resize(64, 64, { fit: "fill" })
    .removeAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  // 8 bins per channel = 512 bins total (R*64 + G*8 + B)
  const bins = new Array(512).fill(0);
  let total = 0;
  for (let i = 0; i < data.length; i += 3) {
    const r = Math.floor(data[i] / 32);
    const g = Math.floor(data[i + 1] / 32);
    const b = Math.floor(data[i + 2] / 32);
    bins[r * 64 + g * 8 + b]++;
    total++;
  }
  // Normalize
  return bins.map(v => v / total);
}

function histogramDistance(h1: number[], h2: number[]): number {
  // Chi-square distance (good for histograms)
  let dist = 0;
  for (let i = 0; i < Math.min(h1.length, h2.length); i++) {
    const sum = h1[i] + h2[i];
    if (sum > 0) {
      const diff = h1[i] - h2[i];
      dist += (diff * diff) / sum;
    }
  }
  return dist;
}

// ============================================================
//  Face detection + descriptor (128-dim embedding)
// ============================================================
async function detectFaceAndDescriptor(buffer: Buffer): Promise<{ descriptor: Float32Array; box: any } | null> {
  try {
    const ok = await initFaceApi();
    if (!ok || !_faceapi || !_tf) return null;
    // Resize to max 1024 wide for performance
    const img = await sharp(buffer).metadata();
    let procBuffer = buffer;
    if (img.width && img.width > 1024) {
      procBuffer = await sharp(buffer).resize(1024, 1024, { fit: "inside" }).toBuffer();
    }
    const { data, info } = await sharp(procBuffer).removeAlpha().raw().toBuffer({ resolveWithObject: true });
    const tensor = _tf.tensor3d(new Uint8Array(data), [info.height, info.width, 3]);
    const detections = await _faceapi
      .detectAllFaces(tensor, new _faceapi.SsdMobilenetv1Options({ minConfidence: 0.2 }))
      .withFaceLandmarks()
      .withFaceDescriptors();
    tensor.dispose();
    if (!detections || detections.length === 0) return null;
    // Use the largest face
    let best = detections[0];
    for (const d of detections) {
      const box = d.detection.box;
      const area = box.width * box.height;
      if (area > best.detection.box.width * best.detection.box.height) best = d;
    }
    return { descriptor: best.descriptor, box: best.detection.box };
  } catch (err: any) {
    console.error("[image-search] face detect error:", err?.message || err);
    return null;
  }
}

// ============================================================
//  Distancia euclidiana entre dos descriptores faciales
//  Valores tipicos:
//    < 0.5: misma persona, alta confianza
//    0.5 - 0.6: misma persona, confianza media
//    > 0.6: persona diferente
// ============================================================
function faceDistance(d1: Float32Array, d2: Float32Array): number {
  let sum = 0;
  const len = Math.min(d1.length, d2.length);
  for (let i = 0; i < len; i++) {
    const diff = d1[i] - d2[i];
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

// ============================================================
//  Sube a tmpfiles.org
// ============================================================
async function uploadToTmpfiles(imageBuffer: Buffer, mime: string): Promise<string | null> {
  try {
    const ext = mime === "image/png" ? "png" : mime === "image/webp" ? "webp" : "jpg";
    const filename = `executive-osint-${Date.now()}.${ext}`;
    const blob = new Blob([imageBuffer], { type: mime });
    const formData = new FormData();
    formData.append("file", blob, filename);
    const r = await fetch("https://tmpfiles.org/api/v1/upload", {
      method: "POST",
      body: formData,
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return null;
    const d: any = await r.json();
    const url: string = d?.data?.url || "";
    if (!url) return null;
    return url.replace("tmpfiles.org/", "tmpfiles.org/dl/");
  } catch (err) {
    console.error("[image-search] tmpfiles upload error:", err);
    return null;
  }
}

// ============================================================
//  Bing Visual Search — obtiene candidatos potenciales
// ============================================================
interface BingCandidate {
  url: string;
  imageUrl: string;
  thumbnailUrl: string;
  title: string;
  width?: number;
  height?: number;
}

async function bingReverseImageSearch(imageUrl: string): Promise<BingCandidate[]> {
  try {
    const url = `https://www.bing.com/images/search?q=&qft=+filterui:photo-photo&tbimg=1&imgurl=${encodeURIComponent(imageUrl)}&tsc=ImageHoverTitle&FORM=IRFLTR`;
    const r = await fetch(url, { headers: htmlFetchHeaders(), signal: AbortSignal.timeout(15000) });
    if (!r.ok) return [];
    const html = await r.text();
    const blockRe = /class="iusc"[^>]*?m="(\{[^"]+\})"/g;
    const matches: BingCandidate[] = [];
    let m: RegExpExecArray | null;
    while ((m = blockRe.exec(html)) && matches.length < 30) {
      try {
        const jsonStr = m[1]
          .replace(/&quot;/g, '"')
          .replace(/&amp;/g, "&")
          .replace(/&lt;/g, "<")
          .replace(/&gt;/g, ">");
        const d = JSON.parse(jsonStr);
        if (!d.murl && !d.purl) continue;
        matches.push({
          url: d.purl || d.murl,
          imageUrl: d.murl || "",
          thumbnailUrl: d.turl || "",
          title: d.title || d.desc || "(no title)",
          width: d.w,
          height: d.h,
        });
      } catch {}
    }
    return matches;
  } catch {
    return [];
  }
}

async function fetchCandidateImage(url: string): Promise<Buffer | null> {
  try {
    const r = await fetch(url, {
      headers: { "User-Agent": htmlFetchHeaders()["User-Agent"] },
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return null;
    const ab = await r.arrayBuffer();
    return Buffer.from(ab);
  } catch {
    return null;
  }
}

// ============================================================
//  Filtrado principal: face match (si hay rostro) o color match
// ============================================================
async function filterMatches(
  originalDescriptor: Float32Array | null,
  originalPHash: string | null,
  originalHistogram: number[] | null,
  candidates: BingCandidate[],
  faceThreshold: number = 0.62, // < 0.5 high, < 0.6 medium, < 0.62 low
  histogramThreshold: number = 0.3,
): Promise<ImageMatch[]> {
  const results: ImageMatch[] = [];
  for (let i = 0; i < candidates.length; i += 6) {
    const batch = candidates.slice(i, i + 6);
    const checked = await Promise.all(batch.map(async (c): Promise<ImageMatch | null> => {
      if (!c.imageUrl) return null;
      const imgBuf = await fetchCandidateImage(c.imageUrl);
      if (!imgBuf || imgBuf.length === 0) return null;
      // 1) Si tenemos descriptor facial de la original, intentamos face match
      if (originalDescriptor) {
        try {
          const candDesc = await detectFaceAndDescriptor(imgBuf);
          if (candDesc) {
            const distance = faceDistance(originalDescriptor, candDesc.descriptor);
            // Convertir a similitud: 0 distance = 100%, >0.62 = 0%
            const similarity = Math.max(0, Math.round(100 - (distance / faceThreshold) * 100));
            if (distance <= faceThreshold) {
              return {
                url: c.url, imageUrl: c.imageUrl, thumbnailUrl: c.thumbnailUrl,
                title: c.title, source: "Face Match (face-api)",
                width: c.width, height: c.height,
                distance, similarity, matchType: "face",
              };
            }
          }
        } catch {}
      }
      // 2) Fallback a histograma de color (imagenes sin rostro)
      if (originalHistogram) {
        try {
          const candHist = await computeColorHistogram(imgBuf);
          const histDist = histogramDistance(originalHistogram, candHist);
          if (histDist <= histogramThreshold) {
            const similarity = Math.max(0, Math.round(100 - (histDist / histogramThreshold) * 100));
            return {
              url: c.url, imageUrl: c.imageUrl, thumbnailUrl: c.thumbnailUrl,
              title: c.title, source: "Color Match (histogram)",
              width: c.width, height: c.height,
              distance: histDist, similarity, matchType: "color",
            };
          }
        } catch {}
      }
      return null;
    }));
    for (const m of checked) if (m) results.push(m);
  }
  // Ordenar: primero face matches (por distancia), luego color
  results.sort((a, b) => {
    if (a.matchType === "face" && b.matchType !== "face") return -1;
    if (b.matchType === "face" && a.matchType !== "face") return 1;
    return a.distance - b.distance;
  });
  return results;
}

export async function POST(request: Request) {
  try {
    const contentType = request.headers.get("content-type") || "";
    let imageBuffer: Buffer | null = null;
    let imageMime = "image/jpeg";

    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      const file = formData.get("image") as File | null;
      if (!file) return NextResponse.json({ error: "missing_image" }, { status: 400 });
      imageMime = file.type || "image/jpeg";
      const ab = await file.arrayBuffer();
      imageBuffer = Buffer.from(ab);
    } else if (contentType.includes("application/json")) {
      const body = await request.json();
      const b64 = body.image as string | undefined;
      if (!b64) return NextResponse.json({ error: "missing_image" }, { status: 400 });
      const match = b64.match(/^data:(image\/[a-zA-Z]+);base64,(.+)$/);
      if (match) {
        imageMime = match[1];
        imageBuffer = Buffer.from(match[2], "base64");
      } else {
        imageMime = "image/jpeg";
        imageBuffer = Buffer.from(b64, "base64");
      }
    } else {
      return NextResponse.json({ error: "unsupported_content_type" }, { status: 400 });
    }

    if (!imageBuffer || imageBuffer.length === 0) {
      return NextResponse.json({ error: "empty_image" }, { status: 400 });
    }

    const tmpDir = "/tmp/executive-osint-images";
    if (!existsSync(tmpDir)) await mkdir(tmpDir, { recursive: true });
    const imgId = `img-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const ext = imageMime === "image/png" ? "png" : imageMime === "image/webp" ? "webp" : "jpg";
    const imgPath = path.join(tmpDir, `${imgId}.${ext}`);
    await writeFile(imgPath, imageBuffer);

    // PASO 1: Detectar rostro en la imagen original + extraer descriptor
    let originalDescriptor: Float32Array | null = null;
    let originalHistogram: number[] | null = null;
    let originalPHash: string | null = null;
    let faceDetected = false;
    try {
      const faceResult = await detectFaceAndDescriptor(imageBuffer);
      if (faceResult && faceResult.descriptor && faceResult.descriptor.length > 0) {
        originalDescriptor = faceResult.descriptor;
        faceDetected = true;
      } else {
        // No face detected -> use color histogram + pHash as fallback
        originalHistogram = await computeColorHistogram(imageBuffer);
      }
    } catch (err) {
      console.error("[image-search] face detect setup error:", err);
      try {
        originalHistogram = await computeColorHistogram(imageBuffer);
      } catch {}
    }

    // PASO 2: Subir a tmpfiles.org
    let publicImageUrl: string | null = null;
    let uploadError: string | null = null;
    try {
      publicImageUrl = await uploadToTmpfiles(imageBuffer, imageMime);
      if (!publicImageUrl) uploadError = "tmpfiles.org upload returned empty URL";
    } catch (e: any) {
      uploadError = String(e?.message || e);
    }

    // PASO 3: Bing Visual Search
    let bingCandidates: BingCandidate[] = [];
    if (publicImageUrl) {
      bingCandidates = await bingReverseImageSearch(publicImageUrl);
    }

    // PASO 4: Filtrar candidatos con face match o color match
    let realMatches: ImageMatch[] = [];
    if (bingCandidates.length > 0 && (originalDescriptor || originalHistogram)) {
      realMatches = await filterMatches(
        originalDescriptor, originalPHash, originalHistogram, bingCandidates,
        0.62, 0.3,
      );
    }

    // PASO 5: URLs de reverse image search
    const engines = publicImageUrl ? [
      {
        source: "Google Images (Reverse)",
        type: "reverse image search",
        url: `https://www.google.com/searchbyimage?image_url=${encodeURIComponent(publicImageUrl)}&sbisrc=tp`,
        snippet: "Google busca coincidencias visuales de la imagen en la web indexada",
        severity: "info",
        instructions: "Click para abrir — Google ejecutara la busqueda automaticamente",
        autoOpen: true,
      },
      {
        source: "Bing Visual Search",
        type: faceDetected ? "face recognition search" : "reverse image search",
        url: `https://www.bing.com/images/search?q=&qft=+filterui:photo-photo&tbimg=1&imgurl=${encodeURIComponent(publicImageUrl)}&tsc=ImageHoverTitle&FORM=IRFLTR`,
        snippet: realMatches.length > 0
          ? `${realMatches.filter(m => m.matchType === "face").length} coincidencias de rostro + ${realMatches.filter(m => m.matchType === "color").length} por color (de ${bingCandidates.length} candidatos)`
          : `Candidatos obtenidos: ${bingCandidates.length}`,
        severity: "high",
        instructions: realMatches.length > 0
          ? `Ver resultados abajo (${realMatches.length} coincidencias reales)`
          : "Click para abrir Bing Visual Search en tu navegador",
        autoOpen: true,
        resultsCount: realMatches.length,
        candidatesCount: bingCandidates.length,
      },
      {
        source: "Yandex Images (Reverse)",
        type: "reverse image search (best for faces)",
        url: `https://yandex.com/images/search?url=${encodeURIComponent(publicImageUrl)}&rpt=imageview`,
        snippet: "Yandex es EL MEJOR motor para reconocer rostros. Muy recomendado para OSINT",
        severity: "high",
        instructions: "Click para abrir Yandex con la imagen cargada",
        autoOpen: true,
      },
      {
        source: "DuckDuckGo Image",
        type: "reverse image search",
        url: `https://duckduckgo.com/?q=${encodeURIComponent(publicImageUrl)}&iax=images&ia=images`,
        snippet: "DuckDuckGo no soporta upload directo, pero puedes buscar la URL de la imagen",
        severity: "info",
        instructions: "Click para abrir DuckDuckGo con la URL de la imagen",
        autoOpen: false,
      },
      {
        source: "Edge (Bing)",
        type: "reverse image search via Edge/Bing",
        url: `https://www.bing.com/images/search?q=&qft=+filterui:photo-photo&tbimg=1&imgurl=${encodeURIComponent(publicImageUrl)}&form=EDGE&setmkt=en-US`,
        snippet: "Edge usa el backend de Bing para la busqueda visual",
        severity: "info",
        instructions: "Click para abrir Bing con el formulario de Edge",
        autoOpen: true,
      },
      {
        source: "TinEye",
        type: "reverse image search (exact match)",
        url: `https://tineye.com/search?url=${encodeURIComponent(publicImageUrl)}`,
        snippet: "TinEye busca coincidencias EXACTAS de la imagen (no similar)",
        severity: "medium",
        instructions: "Click para abrir TinEye con la URL de la imagen",
        autoOpen: true,
      },
      {
        source: "PimEyes (Face Recognition)",
        type: "face search (premium)",
        url: "https://pimeyes.com/",
        snippet: "PimEyes es un motor especializado en reconocimiento facial",
        severity: "high",
        instructions: "Sube la imagen del rostro (idealmente recortada a la cara) manualmente — no acepta URL externa",
        autoOpen: false,
      },
      {
        source: "FaceCheck.ID",
        type: "face search",
        url: "https://facecheck.id/",
        snippet: "FaceCheck.ID busca rostros en redes sociales. Sube la imagen del rostro manualmente",
        severity: "high",
        instructions: "Sube la imagen del rostro manualmente",
        autoOpen: false,
      },
    ] : [
      { source: "Google Images (Reverse)", type: "reverse image search (manual)", url: "https://images.google.com/", snippet: "Sube la imagen manualmente (fallo la subida automatica a hosting publico)", severity: "info", instructions: "Abre el enlace y arrastra tu imagen al buscador", autoOpen: false },
      { source: "Bing Visual Search", type: "reverse image search (manual)", url: "https://www.bing.com/images?form=HDRSC2", snippet: "Sube la imagen manualmente", severity: "info", instructions: "Click en el icono de camara y sube la imagen", autoOpen: false },
      { source: "Yandex Images (Reverse)", type: "reverse image search (best for faces)", url: "https://yandex.com/images", snippet: "Yandex es EL MEJOR motor para reconocer rostros", severity: "high", instructions: "Click en el icono de camara y sube la imagen", autoOpen: false },
      { source: "TinEye", type: "reverse image search (exact match)", url: "https://tineye.com/", snippet: "TinEye busca coincidencias EXACTAS", severity: "medium", instructions: "Sube la imagen o pega su URL", autoOpen: false },
      { source: "PimEyes (Face Recognition)", type: "face search (premium)", url: "https://pimeyes.com/", snippet: "PimEyes: reconocimiento facial especializado", severity: "high", instructions: "Sube la foto del rostro", autoOpen: false },
      { source: "FaceCheck.ID", type: "face search", url: "https://facecheck.id/", snippet: "FaceCheck.ID busca rostros en redes sociales", severity: "high", instructions: "Sube la imagen del rostro", autoOpen: false },
    ];

    const name = new URL(request.url).searchParams.get("name") || "";
    const deepfakeDorks: string[] = [];
    if (name) {
      const cleanName = name.replace(/"/g, "");
      deepfakeDorks.push(
        `"${cleanName}" ("deepfake" OR "deep fake") (filetype:mp4 OR filetype:mkv OR filetype:avi OR site:reddit.com OR site:twitter.com OR site:x.com OR site:youtube.com)`,
        `"${cleanName}" ("deepfake" OR "deep fake" OR "deepfakes" OR "fake video")`,
        `"${cleanName}" (deepfake | "deep fake") (video | synthesis | sintesis | manipulated | manipulado)`,
        `"${cleanName}" site:reddit.com ("deepfake" OR "deep fake")`,
        `"${cleanName}" site:youtube.com ("deepfake" OR "deep fake")`,
      );
    }

    const faceMatchesCount = realMatches.filter(m => m.matchType === "face").length;
    const colorMatchesCount = realMatches.filter(m => m.matchType === "color").length;

    return NextResponse.json({
      imageId: imgId,
      imageSaved: true,
      imageBytes: imageBuffer.length,
      publicImageUrl,
      uploadError,
      faceDetected,
      faceDescriptorDim: originalDescriptor?.length || 0,
      engines,
      imageMatches: realMatches,
      matchCount: realMatches.length,
      candidatesCount: bingCandidates.length,
      filteredOut: Math.max(0, bingCandidates.length - realMatches.length),
      faceMatchesCount,
      colorMatchesCount,
      deepfakeDorks,
      timestamp: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err: any) {
    console.error("[executive-osint/image] ERROR:", err?.message || err, err?.stack || "");
    return NextResponse.json(
      { error: "internal_error", message: String(err?.message || err) },
      { status: 500 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
