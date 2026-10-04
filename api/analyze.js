import { Client, handle_file } from "@gradio/client";
import fs from "fs/promises";
import os from "os";
import path from "path";
import crypto from "crypto";

const SPACE_ID = "saswatpatra/cyberguard_phishing";

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store"
        }
    });
}

async function getClient() {
    const token = process.env.HF_TOKEN;

    if (!token) {
        throw new Error("HF_TOKEN is not configured in Vercel.");
    }

    return await Client.connect(SPACE_ID, {
        token: token
    });
}

async function analyzeMessage(client, message) {
    if (typeof message !== "string" || !message.trim()) {
        throw new Error("Message is required.");
    }

    const result = await client.predict("/analyze_message", {
        message: message.trim()
    });

    return result.data;
}

async function analyzeWebsite(client, url) {
    if (typeof url !== "string" || !url.trim()) {
        throw new Error("Website URL is required.");
    }

    const result = await client.predict("/analyze_website", {
        url: url.trim()
    });

    return result.data;
}

async function analyzeQR(client, imageData, fileName = "qr-image.png") {
    if (typeof imageData !== "string" || !imageData) {
        throw new Error("QR image is required.");
    }

    /*
     * Expected format:
     * data:image/png;base64,....
     */

    let base64Data = imageData;

    if (imageData.includes(",")) {
        base64Data = imageData.split(",")[1];
    }

    const imageBuffer = Buffer.from(base64Data, "base64");

    if (!imageBuffer.length) {
        throw new Error("Invalid QR image data.");
    }

    const safeName = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, "_");

    const tempPath = path.join(
        os.tmpdir(),
        `${crypto.randomUUID()}-${safeName}`
    );

    try {
        await fs.writeFile(tempPath, imageBuffer);

        const result = await client.predict("/scan_qr", {
            image: handle_file(tempPath)
        });

        return result.data;
    } finally {
        try {
            await fs.unlink(tempPath);
        } catch {
            // Ignore cleanup errors.
        }
    }
}

export default {
    async fetch(request) {
        if (request.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type"
                }
            });
        }

        if (request.method !== "POST") {
            return jsonResponse(
                {
                    success: false,
                    error: "Method not allowed. Use POST."
                },
                405
            );
        }

        try {
            const body = await request.json();

            if (!body || typeof body !== "object") {
                return jsonResponse(
                    {
                        success: false,
                        error: "Invalid request body."
                    },
                    400
                );
            }

            const type = body.type;

            if (!type) {
                return jsonResponse(
                    {
                        success: false,
                        error: "Missing analysis type."
                    },
                    400
                );
            }

            const client = await getClient();

            let result;

            switch (type) {
                case "message":
                    result = await analyzeMessage(
                        client,
                        body.message
                    );
                    break;

                case "website":
                    result = await analyzeWebsite(
                        client,
                        body.url
                    );
                    break;

                case "qr":
                    result = await analyzeQR(
                        client,
                        body.image,
                        body.fileName || "qr-image.png"
                    );
                    break;

                default:
                    return jsonResponse(
                        {
                            success: false,
                            error: "Unknown analysis type."
                        },
                        400
                    );
            }

            return jsonResponse({
                success: true,
                type: type,
                result: result
            });

        } catch (error) {
            console.error("CyberGuard API error:", error);

            return jsonResponse(
                {
                    success: false,
                    error: "Analysis request failed.",
                    details:
                        process.env.NODE_ENV === "development"
                            ? String(error.message || error)
                            : undefined
                },
                500
            );
        }
    }
};
