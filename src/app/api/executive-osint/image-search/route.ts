// Executive OSINT — Reverse Image Search con comparacion REAL por hash perceptual
//
// Recibe una imagen (base64 o multipart) y:
//  1. La sube a tmpfiles.org (hosting publico gratuito anonimo, sin API key)
//  2. Calcula el hash perceptual (pHash) de la imagen original con sharp
//  3. Ejecuta Bing Visual Search via imgurl parameter para obtener candidatos
//  4. Descarga cada candidato (murl) y calcula su pHash
//  5. Compara hashes (distancia Hamming) y FILTRA solo coincidencias REALES
//     (distance <= threshold). Ordena por similitud (menor distancia = mas similar)
//  6. Genera URLs de reverse image search para Google/Yandex/Edge/DuckDuckGo/TinEye
//  7. Genera dorks de deepfake usando el nombre del investigado

import { NextResponse } from "next/server";
import { writeFile, mkdir } from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import sharp from "sharp";

interface ImageMatch {
  url: string;          // page URL where image appears (purl)
  imageUrl: string;      // direct image URL (murl)
  thumbnailUrl: string;  // thumbnail (turl)
  title: string;
  source: string;        // engine
  width?: number;
  height?: number;
  distance: number;      // Hamming distance (0 = identical, 1024 = totally different)
  similarity: number;    // 0-100, percentage match (100 = identical)
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
//  Perceptual hash (pHash) usando sharp
//  - Redimensiona a 32x32 grayscale
//  - Bit=1 si pixel > promedio, sino 0
//  - Devuelve string de 1024 bits
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
  // Penaliza diferencia de longitud
  return dist + Math.abs(h1.length - h2.length);
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
  url: string;       // purl (page URL)
  imageUrl: string;  // murl (direct image URL)
  thumbnailUrl: string;
  title: string;
  width?: number;
  height?: number;
}

async function bingReverseImageSearch(imageUrl: string): Promise<BingCandidate[]> {
  try {
    const url = `https://www.bing.com/images/search?q=&qft=+filterui:photo-photo&tbimg=1&imgurl=${encodeURIComponent(imageUrl)}&tsc=ImageHoverTitle&FORM=IRFLTR`;
    const r = await fetch(url, {
      headers: htmlFetchHeaders(),
      signal: AbortSignal.timeout(15000),
    });
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

// ============================================================
//  Compara cada candidato con la imagen original usando pHash
//  - Descarga la imagen del murl (con timeout corto)
//  - Calcula pHash del candidato
//  - Hamming distance: 0 = identica, <=10 = coincidencia fuerte,
//    <=25 = coincidencia posible, >25 = diferente
// ============================================================
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

async function filterRealMatches(
  originalHash: string,
  candidates: BingCandidate[],
  threshold: number = 25,
): Promise<ImageMatch[]> {
  const results: ImageMatch[] = [];
  // Procesa en lotes de 6 en paralelo para no saturar
  for (let i = 0; i < candidates.length; i += 6) {
    const batch = candidates.slice(i, i + 6);
    const checked = await Promise.all(batch.map(async (c): Promise<ImageMatch | null> => {
      if (!c.imageUrl) return null;
      const imgBuf = await fetchCandidateImage(c.imageUrl);
      if (!imgBuf || imgBuf.length === 0) return null;
      try {
        const candidateHash = await computePHash(imgBuf);
        const distance = hammingDistance(originalHash, candidateHash);
        // Similitud: 1024 bits total, 100% = identical
        const similarity = Math.max(0, Math.round(100 - (distance / 1024) * 100));
        if (distance > threshold) return null;  // no es coincidencia real
        return {
          url: c.url,
          imageUrl: c.imageUrl,
          thumbnailUrl: c.thumbnailUrl,
          title: c.title,
          source: "Bing Visual",
          width: c.width,
          height: c.height,
          distance,
          similarity,
        };
      } catch {
        return null;
      }
    }));
    for (const m of checked) if (m) results.push(m);
  }
  // Ordena por similitud descendente (menor distancia = mas similar primero)
  results.sort((a, b) => a.distance - b.distance);
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

    // Guardar la imagen localmente
    const tmpDir = "/tmp/executive-osint-images";
    if (!existsSync(tmpDir)) await mkdir(tmpDir, { recursive: true });
    const imgId = `img-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const ext = imageMime === "image/png" ? "png" : imageMime === "image/webp" ? "webp" : "jpg";
    const imgPath = path.join(tmpDir, `${imgId}.${ext}`);
    await writeFile(imgPath, imageBuffer);

    // PASO 1: Calcular pHash de la imagen original
    let originalHash: string | null = null;
    try {
      originalHash = await computePHash(imageBuffer);
    } catch (err) {
      console.error("[image-search] pHash error:", err);
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

    // PASO 3: Ejecutar Bing Visual Search
    let bingCandidates: BingCandidate[] = [];
    if (publicImageUrl) {
      bingCandidates = await bingReverseImageSearch(publicImageUrl);
    }

    // PASO 4: Comparar cada candidato con la imagen original via pHash
    // Solo se mantienen los que tienen distancia <= 25 (de 1024 bits totales)
    let realMatches: ImageMatch[] = [];
    if (originalHash && bingCandidates.length > 0) {
      realMatches = await filterRealMatches(originalHash, bingCandidates, 25);
    }

    // PASO 5: Generar URLs de reverse image search para los 5 motores
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
        type: realMatches.length > 0 ? "reverse image search (coincidencias reales)" : "reverse image search",
        url: `https://www.bing.com/images/search?q=&qft=+filterui:photo-photo&tbimg=1&imgurl=${encodeURIComponent(publicImageUrl)}&tsc=ImageHoverTitle&FORM=IRFLTR`,
        snippet: realMatches.length > 0
          ? `Comparacion pHash: ${realMatches.length} coincidencias REALES de ${bingCandidates.length} candidatos`
          : `Candidatos obtenidos: ${bingCandidates.length}, ninguno con similitud suficiente`,
        severity: "high",
        instructions: realMatches.length > 0
          ? `Ver resultados abajo (${realMatches.length} coincidencias reales filtradas por pHash)`
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
        snippet: "TinEye busca coincidencias EXACTAS de la imagen (no similar). Util para rastrear donde se publico",
        severity: "medium",
        instructions: "Click para abrir TinEye con la URL de la imagen",
        autoOpen: true,
      },
      {
        source: "PimEyes (Face Recognition)",
        type: "face search (premium)",
        url: "https://pimeyes.com/",
        snippet: "PimEyes es un motor especializado en reconocimiento facial. Encuentra donde aparece este rostro en internet",
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
      // Fallback si tmpfiles.org fallo: solo enlaces a los motores para subida manual
      {
        source: "Google Images (Reverse)",
        type: "reverse image search (manual)",
        url: "https://images.google.com/",
        snippet: "Sube la imagen manualmente (fallo la subida automatica a hosting publico)",
        severity: "info",
        instructions: "Abre el enlace y arrastra tu imagen al buscador",
        autoOpen: false,
      },
      {
        source: "Bing Visual Search",
        type: "reverse image search (manual)",
        url: "https://www.bing.com/images?form=HDRSC2",
        snippet: "Sube la imagen manualmente",
        severity: "info",
        instructions: "Click en el icono de camara y sube la imagen",
        autoOpen: false,
      },
      {
        source: "Yandex Images (Reverse)",
        type: "reverse image search (best for faces)",
        url: "https://yandex.com/images",
        snippet: "Yandex es EL MEJOR motor para reconocer rostros",
        severity: "high",
        instructions: "Click en el icono de camara y sube la imagen",
        autoOpen: false,
      },
      {
        source: "TinEye",
        type: "reverse image search (exact match)",
        url: "https://tineye.com/",
        snippet: "TinEye busca coincidencias EXACTAS",
        severity: "medium",
        instructions: "Sube la imagen o pega su URL",
        autoOpen: false,
      },
      {
        source: "PimEyes (Face Recognition)",
        type: "face search (premium)",
        url: "https://pimeyes.com/",
        snippet: "PimEyes: reconocimiento facial especializado",
        severity: "high",
        instructions: "Sube la foto del rostro",
        autoOpen: false,
      },
      {
        source: "FaceCheck.ID",
        type: "face search",
        url: "https://facecheck.id/",
        snippet: "FaceCheck.ID busca rostros en redes sociales",
        severity: "high",
        instructions: "Sube la imagen del rostro",
        autoOpen: false,
      },
    ];

    // Dorks deepfake basados en el nombre (si se proporciona)
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

    return NextResponse.json({
      imageId: imgId,
      imageSaved: true,
      imageBytes: imageBuffer.length,
      publicImageUrl,
      uploadError,
      originalHashBits: originalHash?.length || 0,
      engines,
      // Coincidencias REALES filtradas por pHash (similitud verdadera)
      imageMatches: realMatches,
      matchCount: realMatches.length,
      // Candidatos totales devueltos por Bing antes del filtro
      candidatesCount: bingCandidates.length,
      filteredOut: Math.max(0, bingCandidates.length - realMatches.length),
      threshold: 25,
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
