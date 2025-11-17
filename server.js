// server.js
// Worker: downloads PDF from SF, calls Gemini, parses JSON, writes records back to SF.
// Uses JWT Bearer flow for SF (SF_PRIVATE_KEY required).
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

if (!WORKER_SECRET) throw new Error("WORKER_SECRET required in .env");
if (!GEMINI_ENDPOINT || !GEMINI_API_KEY)
  throw new Error("GEMINI_ENDPOINT and GEMINI_API_KEY required in .env");
if (!SF_LOGIN_URL || !SF_CLIENT_ID || !SF_USERNAME)
  throw new Error("SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME required in .env");
if (!SF_PRIVATE_KEY)
  throw new Error("SF_PRIVATE_KEY required in .env for JWT flow");

const API_VERSION = "v58.0";
const app = express();
app.use(bodyParser.json({ limit: "20mb" }));

// Temporary: log every incoming request (helps confirm Render receives requests)
app.use((req, res, next) => {
  console.log(
    "INCOMING:",
    req.method,
    req.url,
    "hasSecret=",
    !!req.headers["x-worker-secret"]
  );
  next();
});

// health endpoint
app.get("/health", (req, res) => {
  console.log("HEALTH CHECK at", new Date().toISOString());
  res.json({ ok: true, ts: Date.now() });
});

// normalize private key (allow \n encoded)
function normalizePrivateKey(pk) {
  if (!pk) return pk;
  if (pk.indexOf("\\n") !== -1) return pk.replace(/\\n/g, "\n");
  return pk;
}
const PRIVATE_KEY = normalizePrivateKey(SF_PRIVATE_KEY);

// === Salesforce JWT flow: returns { accessToken, instanceUrl } ===
async function getSalesforceAccessTokenViaJWT() {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: SF_CLIENT_ID,
    sub: SF_USERNAME,
    aud: SF_LOGIN_URL,
    exp: now + 180,
  };

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
  return {
    accessToken: res.data.access_token,
    instanceUrl: res.data.instance_url,
  };
}

// === Salesforce helpers (use instanceUrl returned by token) ===
async function downloadContentVersion(versionId, accessToken, instanceUrl) {
  const url = `${instanceUrl}/services/data/${API_VERSION}/sobjects/ContentVersion/${versionId}/VersionData`;
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

async function createSObject(sobjectName, body, accessToken, instanceUrl) {
  const url = `${instanceUrl}/services/data/${API_VERSION}/sobjects/${sobjectName}/`;
  try {
    const r = await axios.post(url, body, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    console.log(`SF create ${sobjectName} success:`, r.data);
    return r.data;
  } catch (err) {
    const sfErr = err.response ? err.response.data : err.message;
    console.error(`SF create ${sobjectName} failed:`, sfErr, "payload:", body);
    throw new Error(
      `SF create ${sobjectName} failed: ${JSON.stringify(sfErr)}`
    );
  }
}

async function querySalesforce(soql, accessToken, instanceUrl) {
  const url = `${instanceUrl}/services/data/${API_VERSION}/query/?q=${encodeURIComponent(
    soql
  )}`;
  try {
    const r = await axios.get(url, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return r.data;
  } catch (err) {
    const body = err.response ? JSON.stringify(err.response.data) : err.message;
    throw new Error("SF SOQL query failed: " + body);
  }
}

async function createContentDocumentLink(
  contentDocumentId,
  linkedEntityId,
  accessToken,
  instanceUrl
) {
  const url = `${instanceUrl}/services/data/${API_VERSION}/sobjects/ContentDocumentLink/`;
  const body = {
    ContentDocumentId: contentDocumentId,
    LinkedEntityId: linkedEntityId,
    ShareType: "V",
    Visibility: "AllUsers",
  };
  try {
    const r = await axios.post(url, body, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return r.data;
  } catch (err) {
    const body = err.response ? JSON.stringify(err.response.data) : err.message;
    throw new Error("Failed to create ContentDocumentLink: " + body);
  }
}

// Save raw Gemini response to ContentVersion for manual inspection (base64 encode VersionData)
async function saveGeminiRespToContentVersion(
  geminiRaw,
  originContentVersionId,
  accessToken,
  instanceUrl
) {
  try {
    const title = `gemini_resp_${Date.now()}.json`;
    const url = `${instanceUrl}/services/data/${API_VERSION}/sobjects/ContentVersion/`;
    // For ContentVersion via REST, VersionData must be base64 encoded
    const body = {
      Title: title,
      PathOnClient: title,
      VersionData: Buffer.from(geminiRaw).toString("base64"),
      // Optionally you can set FirstPublishLocationId or other metadata if needed
    };
    const r = await axios.post(url, body, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    console.log("Saved Gemini raw response as ContentVersion id:", r.data.id);
    return r.data;
  } catch (err) {
    console.error(
      "Failed to save Gemini raw response to ContentVersion:",
      err.response ? err.response.data : err.message
    );
    return null;
  }
}

// === Gemini call ===
async function callGeminiWithPdfBase64(base64Pdf, prompt) {
  const url = `${GEMINI_ENDPOINT}?key=${GEMINI_API_KEY}`;
  const payload = {
    contents: [
      {
        parts: [
          { text: prompt },
          { inline_data: { mime_type: "application/pdf", data: base64Pdf } },
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

// extract textual candidate from Gemini response
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

// naive but useful: extract JSON substring and parse
function extractJsonFromText(text) {
  if (!text) return null;
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first >= 0 && last > first) {
    const sub = text.substring(first, last + 1);
    try {
      return JSON.parse(sub);
    } catch (e) {
      // try sanitizing control chars then parse
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

// verify worker secret middleware
function verifyWorkerSecret(req, res, next) {
  const secretHeader =
    req.headers["x-worker-secret"] || req.headers["x-worker-token"];
  if (!secretHeader || secretHeader !== WORKER_SECRET) {
    console.warn("Invalid or missing worker secret header");
    return res.status(401).json({ error: "Invalid worker secret" });
  }
  next();
}

// ---------------- main endpoint ----------------
app.post("/process", verifyWorkerSecret, async (req, res) => {
  try {
    const { contentDocumentId, originContentVersionId, linkedOpportunityId } =
      req.body;
    if (!originContentVersionId)
      return res.status(400).json({ error: "originContentVersionId required" });

    console.log("Job received for version:", originContentVersionId);

    // 1) get SF token and instance URL
    const tokenResp = await getSalesforceAccessTokenViaJWT();
    const accessToken = tokenResp.accessToken;
    const instanceUrl = tokenResp.instanceUrl;
    console.log("Got SF access token and instanceUrl:", instanceUrl);

    // 2) download PDF (VersionData)
    const pdfBuf = await downloadContentVersion(
      originContentVersionId,
      accessToken,
      instanceUrl
    );
    console.log("Downloaded PDF bytes:", pdfBuf.length);

    // 3) call Gemini
    const base64Pdf = pdfBuf.toString("base64");
    const prompt = `Extract the details and return only valid JSON. Do not include markdown, comments, or text outside the JSON object.
{ "patientName": "", "claimedAmount": "", "approvedAmount": "", "lineItems": [ { "lineNumber": "", "productName": "", "description": "", "quantity": "", "unit": "", "rcv": "", "depreciation": "", "acv": "", "tax": "", "op": "", "section": "" } ] }.
Return valid JSON only.`;
    const geminiResp = await callGeminiWithPdfBase64(base64Pdf, prompt);
    console.log("Gemini response received");

    // 4) extract text and parse json
    const text = extractTextFromGeminiResp(geminiResp);
    if (!text) {
      console.warn(
        "No text field in Gemini response; saving full geminiResp to SF for inspection"
      );
      await saveGeminiRespToContentVersion(
        JSON.stringify(geminiResp),
        originContentVersionId,
        accessToken,
        instanceUrl
      );
      return res.status(500).json({
        error: "No text field in Gemini response",
        geminiRespSummary:
          geminiResp && geminiResp.candidates
            ? geminiResp.candidates.length + " candidates"
            : "noCandidates",
      });
    }

    const parsed = extractJsonFromText(text);
    if (!parsed) {
      console.warn(
        "Failed to parse JSON from Gemini text; saving geminiResp to SF for inspection"
      );
      await saveGeminiRespToContentVersion(
        JSON.stringify(geminiResp),
        originContentVersionId,
        accessToken,
        instanceUrl
      );
      return res.status(500).json({
        error: "Failed to parse JSON from Gemini output",
        sampleText: text.substring(0, 2000),
      });
    }

    // 5) create claim
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
      accessToken,
      instanceUrl
    );
    const claimId = claimResult.id;
    console.log("Created claim:", claimId);

    // 6) line items & products
    if (Array.isArray(parsed.lineItems)) {
      for (const li of parsed.lineItems) {
        const prodName =
          li.productName ||
          (li.description || "").substring(0, 60) ||
          "Unnamed Product";

        // find existing product
        let productId = null;
        try {
          const q = `SELECT Id, Name FROM Product2 WHERE Name = '${prodName.replace(
            /'/g,
            "\\'"
          )}' LIMIT 1`;
          const qres = await querySalesforce(q, accessToken, instanceUrl);
          if (qres.records && qres.records.length > 0)
            productId = qres.records[0].Id;
        } catch (err) {
          console.warn("Product lookup failed", err.message || err);
        }

        if (!productId) {
          try {
            const pr = await createSObject(
              "Product2",
              { Name: prodName },
              accessToken,
              instanceUrl
            );
            productId = pr.id;
            console.log("Created Product2:", productId);
          } catch (err) {
            console.warn("Failed to create Product2", err.message || err);
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
            accessToken,
            instanceUrl
          );
          console.log("Created Insurance_Product__c", ipRes.id);
        } catch (err) {
          console.warn(
            "Failed to create Insurance_Product__c",
            err.message || err
          );
        }
      }
    }

    // 7) link content document to claim
    if (contentDocumentId && claimId) {
      try {
        await createContentDocumentLink(
          contentDocumentId,
          claimId,
          accessToken,
          instanceUrl
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
