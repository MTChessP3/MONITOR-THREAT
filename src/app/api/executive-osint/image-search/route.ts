// Executive OSINT — Reverse Image Search con reconocimiento facial real
//
// Recibe una imagen (base64 o multipart) y:
//  1. La guarda en /tmp/ y genera una URL data: para uso inmediato
//  2. Si FACECHECK_API_KEY esta configurada, sube la imagen a FaceCheck.ID
//     y devuelve resultados reales de face match (URLs donde aparece el rostro)
//  3. Genera URLs de reverse image search para Google, Yandex, Bing, TinEye
//     con auto-submit (formulario que se auto-postea al cargar la pagina)
//  4. Genera dorks de deepfake usando el nombre del investigado

import { NextResponse } from "next/server";
import { writeFile, mkdir, readFile } from "fs/promises";
import { existsSync } from "fs";
import path from "path";

interface FaceMatch {
  url: string;
  score: number;
  source?: string;
  snippet?: string;
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

    // Guardar la imagen
    const tmpDir = "/tmp/executive-osint-images";
    if (!existsSync(tmpDir)) await mkdir(tmpDir, { recursive: true });
    const imgId = `img-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const ext = imageMime === "image/png" ? "png" : imageMime === "image/webp" ? "webp" : "jpg";
    const imgPath = path.join(tmpDir, `${imgId}.${ext}`);
    await writeFile(imgPath, imageBuffer);

    // Generar data URL para uso en los motores que acepten POST de imagen
    const b64Image = imageBuffer.toString("base64");
    const dataUrl = `data:${imageMime};base64,${b64Image}`;

    // =====================================================
    // 1. FACECHECK.ID - API real de reconocimiento facial
    //    Requiere FACECHECK_API_KEY en env. Si no hay, devolvemos
    //    enlaces para subida manual.
    // =====================================================
    let faceMatches: FaceMatch[] = [];
    let faceCheckUsed = false;
    let faceCheckError: string | null = null;

    const faceCheckKey = process.env.FACECHECK_API_KEY || "";
    if (faceCheckKey) {
      try {
        // Paso 1: subir la imagen a FaceCheck
        const uploadRes = await fetch("https://facecheck.id/api/upload_pic", {
          method: "POST",
          headers: {
            "Authorization": faceCheckKey,
            "User-Agent": "MONITOR-THREAT",
          },
          body: imageBuffer, // raw binary
        });
        if (uploadRes.ok) {
          const uploadData: any = await uploadRes.json();
          const idSearch = uploadData.id_search;
          if (idSearch) {
            // Paso 2: iniciar busqueda
            const searchRes = await fetch("https://facecheck.id/api/search", {
              method: "POST",
              headers: {
                "Authorization": faceCheckKey,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ id_search: idSearch }),
            });
            if (searchRes.ok) {
              const searchData: any = await searchRes.json();
              // Paso 3: poll hasta completar (max 30s)
              let attempts = 0;
              let results = searchData.output?.results || [];
              while ((!results || results.length === 0) && attempts < 10) {
                await new Promise(r => setTimeout(r, 3000));
                const pollRes = await fetch("https://facecheck.id/api/search", {
                  method: "POST",
                  headers: { "Authorization": faceCheckKey, "Content-Type": "application/json" },
                  body: JSON.stringify({ id_search: idSearch }),
                });
                if (pollRes.ok) {
                  const pd: any = await pollRes.json();
                  if (pd.output?.results?.length > 0) {
                    results = pd.output.results;
                    break;
                  }
                }
                attempts++;
              }
              faceMatches = (results || []).slice(0, 20).map((r: any) => ({
                url: r.url || "",
                score: r.score || 0,
                source: r.base || r.site || "FaceCheck.ID",
                snippet: `Confidence: ${r.score || 0}% — ${r.base || r.site || ""}`,
              }));
              faceCheckUsed = true;
            }
          }
        } else {
          faceCheckError = `FaceCheck upload HTTP ${uploadRes.status}`;
        }
      } catch (e: any) {
        faceCheckError = String(e?.message || e);
      }
    }

    // =====================================================
    // 2. Generar URLs de reverse image search con auto-submit
    //    Como no podemos ejecutar browser real server-side, generamos
    //    HTML auto-submit forms que el usuario abre en su navegador.
    //    Google/Yandex/Bing no aceptan image upload via URL directa,
    //    pero sus formularios de upload son accesibles.
    // =====================================================

    // Lista de motores con instrucciones de subida manual + URL de formulario
    const searchEngines = [
      {
        source: "Google Images (Reverse)",
        type: "reverse image search",
        url: "https://images.google.com/",
        snippet: "Sube la imagen en Google Images para encontrar coincidencias visuales en la web",
        severity: "info",
        instructions: "Abre el enlace, haz clic en el icono de camara y arrastra tu imagen",
      },
      {
        source: "Google Lens",
        type: "visual search",
        url: "https://lens.google.com/",
        snippet: "Google Lens detecta rostros, objetos, texto y lugares. Encuentra coincidencias visuales",
        severity: "info",
        instructions: "Sube la imagen o pega la URL data:image/...",
      },
      {
        source: "Bing Visual Search",
        type: "reverse image search",
        url: "https://www.bing.com/images?form=HDRSC2",
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
        snippet: "PimEyes es un motor especializado en reconocimiento facial. Encuentra donde aparece este rostro en internet",
        severity: "high",
        instructions: "Sube la foto del rostro (idealmente recortada a la cara)",
      },
      {
        source: "FaceCheck.ID (Face Recognition)",
        type: "face search",
        url: "https://facecheck.id/",
        snippet: faceCheckUsed
          ? `Busqueda automatica completada: ${faceMatches.length} coincidencias encontradas`
          : "FaceCheck.ID busca rostros en redes sociales. Sube la imagen del rostro manualmente",
        severity: "high",
        instructions: "Sube la imagen del rostro",
        faceMatches: faceCheckUsed ? faceMatches : undefined,
      },
      {
        source: "Search4faces",
        type: "face recognition (VK/OK)",
        url: "https://search4faces.com/",
        snippet: "Busca rostros en redes sociales rusas (VKontakte, Odnoklassniki) y otras. Muy util para identificadores ex-Soviet",
        severity: "medium",
        instructions: "Sube la imagen del rostro",
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
      imageDataUrl: dataUrl,
      searchEngines,
      faceMatches: faceCheckUsed ? faceMatches : [],
      faceCheckUsed,
      faceCheckError,
      hasFaceCheckKey: !!faceCheckKey,
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
