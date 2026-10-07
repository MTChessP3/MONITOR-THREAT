// Executive OSINT — Reverse Image Search
// Recibe una imagen (base64 o multipart), la guarda en /tmp/, y devuelve
// enlaces directos a motores de reverse image + face search + dorks de deepfake.

import { NextResponse } from "next/server";
import { writeFile, mkdir } from "fs/promises";
import { existsSync } from "fs";
import path from "path";

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

    const searchEngines = [
      {
        source: "Google Images (Reverse)",
        type: "reverse image search",
        url: "https://images.google.com/",
        snippet: "Sube la imagen en Google Images para encontrar coincidencias visuales en la web",
        severity: "info",
        instructions: "Abre el enlace y arrastra tu imagen al buscador",
      },
      {
        source: "Google Lens",
        type: "visual search",
        url: "https://lens.google.com/",
        snippet: "Google Lens detecta rostros, objetos, texto y lugares. Encuentra coincidencias visuales",
        severity: "info",
        instructions: "Sube la imagen o pega la URL de la imagen ya cargada",
      },
      {
        source: "Bing Visual Search",
        type: "reverse image search",
        url: "https://www.bing.com/images",
        snippet: "Bing Visual Search permite buscar por imagen, con deteccion de rostros",
        severity: "info",
        instructions: "Click en el icono de camara y sube la imagen",
      },
      {
        source: "Yandex Images (Reverse)",
        type: "reverse image search (best for faces)",
        url: "https://yandex.com/images",
        snippet: "Yandex es EL MEJOR motor para reconocer rostros. Muy recomendado para OSINT",
        severity: "high",
        instructions: "Click en el icono de camara y sube la imagen",
      },
      {
        source: "TinEye",
        type: "reverse image search (exact match)",
        url: "https://tineye.com/",
        snippet: "TinEye busca coincidencias EXACTAS de la imagen (no similar). Util para rastrear donde se publico",
        severity: "medium",
        instructions: "Sube la imagen o pega su URL",
      },
      {
        source: "PimEyes (Face Recognition)",
        type: "face search (premium)",
        url: "https://pimeyes.com/",
        snippet: "PimEyes es un motor especializado en reconocimiento facial",
        severity: "high",
        instructions: "Sube la foto del rostro (idealmente recortada a la cara)",
      },
      {
        source: "FaceCheck.ID",
        type: "face search",
        url: "https://facecheck.id/",
        snippet: "FaceCheck busca rostros en redes sociales y sitios publicos",
        severity: "high",
        instructions: "Sube la imagen del rostro",
      },
      {
        source: "Search4faces",
        type: "face recognition (VK/OK)",
        url: "https://search4faces.com/",
        snippet: "Busca rostros en redes sociales rusas (VKontakte, Odnoklassniki)",
        severity: "medium",
        instructions: "Sube la imagen del rostro",
      },
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

    return NextResponse.json({
      imageId: imgId,
      imageSaved: true,
      imageBytes: imageBuffer.length,
      searchEngines,
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
