// server.js
// Worker service: downloads PDF from Salesforce, calls Gemini, parses JSON, writes records back to Salesforce.
// Uses JWT Bearer flow for Salesforce (requires SF_PRIVATE_KEY, SF_CLIENT_ID, SF_USERNAME).
//
// Required env vars:
//  - WORKER_SECRET
//  - GEMINI_ENDPOINT
//  - GEMINI_API_KEY
//  - SF_LOGIN_URL          (e.g. https://login.salesforce.com or https://test.salesforce.com)
//  - SF_CLIENT_ID
//  - SF_USERNAME
//  - SF_PRIVATE_KEY        (supports "\n" escaped newlines)
// Optional:
//  - PORT
//
// npm i express axios body-parser dotenv jsonwebtoken

const express = require("express");
const axios = require("axios");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const {
  WORKER_SECRET,
  GEMINI_ENDPOINT,
  GEMINI_API_KEY,
  SF_LOGIN_URL,
  SF_CLIENT_ID,
  SF_USERNAME,
  SF_PRIVATE_KEY,
  PORT = 3000,
} = process.env;

if (!WORKER_SECRET) throw new Error("WORKER_SECRET is required in .env");
if (!GEMINI_ENDPOINT || !GEMINI_API_KEY)
  throw new Error("GEMINI_ENDPOINT and GEMINI_API_KEY required in .env");
if (!SF_LOGIN_URL || !SF_CLIENT_ID || !SF_USERNAME)
  throw new Error("SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME required in .env");
if (!SF_PRIVATE_KEY)
  throw new Error("SF_PRIVATE_KEY required in .env for JWT flow");

const API_VERSION = "v58.0";

const app = express();
app.use(bodyParser.json({ limit: "10mb" }));

// Normalize private key: allow user to store with \n sequences in .env
function normalizePrivateKey(pk) {
  if (!pk) return pk;
  // If it already contains newlines, return as-is
  if (pk.indexOf("\\n") !== -1) {
    return pk.replace(/\\n/g, "\n");
  }
  return pk;
}
const PRIVATE_KEY = normalizePrivateKey(SF_PRIVATE_KEY);

// Create a Salesforce access token using JWT Bearer flow
async function getSalesforceAccessTokenViaJWT() {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: SF_CLIENT_ID, // client id (connected app)
    sub: SF_USERNAME, // username of integration user
    aud: SF_LOGIN_URL, // audience: login.salesforce.com or test.salesforce.com
    exp: now + 180, // short expiry (3 minutes)
  };

  // Sign JWT using RSA SHA256
  const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: "RS256" });

  const url = `${SF_LOGIN_URL}/services/oauth2/token`;
  const params = new URLSearchParams();
  params.append("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  params.append("assertion", token);

  const res = await axios.post(url, params).catch((err) => {
    const body = err.response ? JSON.stringify(err.response.data) : err.message;
    throw new Error("Failed to get SF access token (JWT): " + body);
  });

  if (!res.data || !res.data.access_token)
    throw new Error("No access_token in SF JWT token response");
  return res.data.access_token;
}

// Download ContentVersion VersionData bytes
async function downloadContentVersion(versionId, accessToken) {
  const url = `${SF_LOGIN_URL}/services/data/${API_VERSION}/sobjects/ContentVersion/${versionId}/VersionData`;
  const r = await axios
    .get(url, {
      responseType: "arraybuffer",
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    .catch((err) => {
      const body = err.response
        ? JSON.stringify(err.response.data)
        : err.message;
      throw new Error("Failed to download ContentVersion VersionData: " + body);
    });
  return Buffer.from(r.data);
}

// Create generic SObject via REST API
async function createSObject(sobjectName, body, accessToken) {
  const url = `${SF_LOGIN_URL}/services/data/${API_VERSION}/sobjects/${sobjectName}/`;
  const r = await axios
    .post(url, body, { headers: { Authorization: `Bearer ${accessToken}` } })
    .catch((err) => {
      const body = err.response
        ? JSON.stringify(err.response.data)
        : err.message;
      throw new Error(`Failed to create ${sobjectName}: ${body}`);
    });
  return r.data;
}

// Query helper
async function querySalesforce(soql, accessToken) {
  const url = `${SF_LOGIN_URL}/services/data/${API_VERSION}/query/?q=${encodeURIComponent(
    soql
  )}`;
  const r = await axios
    .get(url, { headers: { Authorization: `Bearer ${accessToken}` } })
    .catch((err) => {
      const body = err.response
        ? JSON.stringify(err.response.data)
        : err.message;
      throw new Error("SF SOQL query failed: " + body);
    });
  return r.data;
}

// Create ContentDocumentLink
async function createContentDocumentLink(
  contentDocumentId,
  linkedEntityId,
  accessToken
) {
  const url = `${SF_LOGIN_URL}/services/data/${API_VERSION}/sobjects/ContentDocumentLink/`;
  const body = {
    ContentDocumentId: contentDocumentId,
    LinkedEntityId: linkedEntityId,
    ShareType: "V",
    Visibility: "AllUsers",
  };
  const r = await axios
    .post(url, body, { headers: { Authorization: `Bearer ${accessToken}` } })
    .catch((err) => {
      const body = err.response
        ? JSON.stringify(err.response.data)
        : err.message;
      throw new Error("Failed to create ContentDocumentLink: " + body);
    });
  return r.data;
}

// Call Gemini with base64 PDF inline
async function callGeminiWithPdfBase64(base64Pdf, prompt) {
  const url = `${GEMINI_ENDPOINT}?key=${GEMINI_API_KEY}`;
  const payload = {
    contents: [
      {
        parts: [
          { text: prompt },
          {
            inline_data: {
              mime_type: "application/pdf",
              data: base64Pdf,
            },
          },
        ],
      },
    ],
  };
  const r = await axios.post(url, payload, { timeout: 120000 }).catch((err) => {
    const body = err.response ? JSON.stringify(err.response.data) : err.message;
    throw new Error("Gemini call failed: " + body);
  });
  return r.data;
}

// Extract text (candidate content) from Gemini response
function extractTextFromGeminiResp(geminiResp) {
  if (!geminiResp) return null;
  const candidates = geminiResp.candidates;
  if (!Array.isArray(candidates) || candidates.length === 0) return null;
  const content = candidates[0].content;
  if (!content || !Array.isArray(content.parts) || content.parts.length === 0)
    return null;
  for (const p of content.parts) {
    if (p && typeof p.text === "string") return p.text;
  }
  return null;
}

// Best-effort JSON extraction from text
function extractJsonFromText(text) {
  if (!text) return null;
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first >= 0 && last > first) {
    const sub = text.substring(first, last + 1);
    try {
      return JSON.parse(sub);
    } catch (e) {
      // try sanitize control chars
      const sanitized = sub.replace(/[\x00-\x1F\x7F]/g, "");
      try {
        return JSON.parse(sanitized);
      } catch (e2) {
        return null;
      }
    }
  }
  return null;
}

// Middleware: verify worker secret
function verifyWorkerSecret(req, res, next) {
  const secretHeader =
    req.headers["x-worker-secret"] || req.headers["x-worker-token"];
  if (!secretHeader || secretHeader !== WORKER_SECRET) {
    return res.status(401).json({ error: "Invalid worker secret" });
  }
  next();
}

// Main endpoint
app.post("/process", verifyWorkerSecret, async (req, res) => {
  try {
    const { contentDocumentId, originContentVersionId, linkedOpportunityId } =
      req.body;
    if (!originContentVersionId)
      return res.status(400).json({ error: "originContentVersionId required" });

    console.log("Job received for version:", originContentVersionId);

    // 1) SF access token via JWT
    const accessToken = await getSalesforceAccessTokenViaJWT();

    // 2) Download PDF bytes
    const pdfBuf = await downloadContentVersion(
      originContentVersionId,
      accessToken
    );
    console.log("Downloaded PDF bytes:", pdfBuf.length);

    // 3) Call Gemini
    const base64Pdf = pdfBuf.toString("base64");
    const prompt = `Extract the details and return only valid JSON. Do not include markdown, comments, or text outside the JSON object.
{ "patientName": "", "claimedAmount": "", "approvedAmount": "", "lineItems": [ { "lineNumber": "", "productName": "", "description": "", "quantity": "", "unit": "", "rcv": "", "depreciation": "", "acv": "", "tax": "", "op": "", "section": "" } ] }.
Return valid JSON only.`;
    const geminiResp = await callGeminiWithPdfBase64(base64Pdf, prompt);
    console.log("Gemini response received");

    // 4) Extract & parse JSON
    const text = extractTextFromGeminiResp(geminiResp);
    if (!text)
      return res.status(500).json({
        error: "No textual candidate found in Gemini response",
        geminiResp,
      });

    const parsed = extractJsonFromText(text);
    if (!parsed) {
      // optional: save full geminiResp to SF for manual inspection (omitted here)
      return res
        .status(500)
        .json({ error: "Failed to parse JSON from Gemini text", text });
    }

    // 5) Create Insurance_Claim__c
    const claimBody = {
      Name: parsed.patientName
        ? parsed.patientName + " - Claim"
        : "Claim " + Date.now(),
      Patient_Name__c: parsed.patientName || null,
      Claimed_Amount__c: parsed.claimedAmount || null,
      Approved_Amount__c: parsed.approvedAmount || null,
      Opportunity__c: linkedOpportunityId || null,
    };
    const claimResult = await createSObject(
      "Insurance_Claim__c",
      claimBody,
      accessToken
    );
    const claimId = claimResult.id;
    console.log("Created claim:", claimId);

    // 6) Line items & products
    if (Array.isArray(parsed.lineItems)) {
      for (const li of parsed.lineItems) {
        const prodName =
          li.productName ||
          (li.description || "").substring(0, 60) ||
          "Unnamed Product";

        // Try find existing product
        let productId = null;
        try {
          const q = `SELECT Id, Name FROM Product2 WHERE Name = '${prodName.replace(
            /'/g,
            "\\'"
          )}' LIMIT 1`;
          const qres = await querySalesforce(q, accessToken);
          if (qres.records && qres.records.length > 0)
            productId = qres.records[0].Id;
        } catch (err) {
          console.warn("Product lookup error:", err.message || err);
        }

        if (!productId) {
          try {
            const pr = await createSObject(
              "Product2",
              { Name: prodName },
              accessToken
            );
            productId = pr.id;
          } catch (err) {
            console.warn("Failed to create Product2:", err.message || err);
          }
        }

        const ipBody = {
          Insurance_Claim__c: claimId,
          Description__c: li.description || null,
          Quantity__c: li.quantity ? Number(li.quantity) : null,
          Unit__c: li.unit || null,
          RCV_Amount__c: li.rcv || null,
          Depreciation_Amount__c: li.depreciation || null,
          ACV_Amount__c: li.acv || null,
          TAX_Amount__c: li.tax || null,
          OP_Amount__c: li.op || null,
          Section__c: li.section || null,
        };
        if (productId) ipBody.Product__c = productId;

        try {
          const ipRes = await createSObject(
            "Insurance_Product__c",
            ipBody,
            accessToken
          );
          console.log("Created Insurance_Product__c", ipRes.id);
        } catch (err) {
          console.warn(
            "Failed to create Insurance_Product__c:",
            err.message || err
          );
        }
      }
    }

    // 7) Link ContentDocument <-> Claim
    if (contentDocumentId && claimId) {
      try {
        await createContentDocumentLink(
          contentDocumentId,
          claimId,
          accessToken
        );
        console.log("Linked ContentDocument to claim");
      } catch (err) {
        console.warn(
          "Failed to create ContentDocumentLink:",
          err.message || err
        );
      }
    }

    return res.status(200).json({ ok: true, claimId });
  } catch (err) {
    console.error("Worker error:", (err && err.message) || err);
    return res.status(500).json({ error: (err && err.message) || String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Worker listening on port ${PORT}`);
});
