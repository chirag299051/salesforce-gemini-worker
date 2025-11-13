// server.js
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const jsforce = require("jsforce");
const axios = require("axios");
const FormData = require("form-data");

const app = express();
app.use(bodyParser.json({ limit: "10mb" })); // small notifications only

const PORT = process.env.PORT || 8080;
const WORKER_SECRET = process.env.WORKER_SECRET; // must match Named Credential header
const GEMINI_ENDPOINT = process.env.GEMINI_ENDPOINT; // e.g. https://your-gemini-proxy.example.com/analyze
const GEMINI_API_KEY = process.env.GEMINI_API_KEY; // if needed by your Gemini/proxy
const SF_LOGIN_URL = process.env.SF_LOGIN_URL || "https://login.salesforce.com";
const SF_CLIENT_ID = process.env.SF_CLIENT_ID;
const SF_USERNAME = process.env.SF_USERNAME;
const SF_PRIVATE_KEY = process.env.SF_PRIVATE_KEY; // PEM content, newlines escaped as \n or actual newlines

if (
  !WORKER_SECRET ||
  !GEMINI_ENDPOINT ||
  !SF_CLIENT_ID ||
  !SF_USERNAME ||
  !SF_PRIVATE_KEY
) {
  console.error("Missing required env vars. See README.");
  process.exit(1);
}

const jwt = require("jsonwebtoken");
const querystring = require("querystring");

// helper: perform JWT Bearer flow and return an authenticated jsforce Connection
async function getSalesforceConnection() {
  // Required env vars: SF_LOGIN_URL, SF_CLIENT_ID, SF_USERNAME, SF_PRIVATE_KEY
  const loginUrl = process.env.SF_LOGIN_URL || "https://login.salesforce.com";
  const clientId = process.env.SF_CLIENT_ID;
  const username = process.env.SF_USERNAME;
  const privateKey = process.env.SF_PRIVATE_KEY;

  if (!clientId || !username || !privateKey) {
    throw new Error(
      "Missing Salesforce JWT config (SF_CLIENT_ID, SF_USERNAME, SF_PRIVATE_KEY)"
    );
  }

  // Build JWT payload
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientId, // Connected App Consumer Key
    sub: username, // Salesforce user to impersonate
    aud: loginUrl, // audience: login URL
    exp: nowSec + 300, // expires in 5 minutes
  };

  // Sign JWT with RS256 using your private key (PEM)
  const token = jwt.sign(payload, privateKey, { algorithm: "RS256" });

  // Exchange JWT for an access token
  const tokenUrl = `${loginUrl}/services/oauth2/token`;
  const body = querystring.stringify({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: token,
  });

  const tokenResp = await axios.post(tokenUrl, body, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });

  if (!tokenResp || tokenResp.status !== 200) {
    throw new Error(
      "Failed to obtain Salesforce access token: " +
        (tokenResp && tokenResp.status)
    );
  }

  const data = tokenResp.data;
  if (!data.access_token || !data.instance_url) {
    throw new Error(
      "Salesforce token response missing access_token or instance_url: " +
        JSON.stringify(data)
    );
  }

  // Create jsforce connection using the token
  const conn = new jsforce.Connection({
    instanceUrl: data.instance_url,
    accessToken: data.access_token,
  });

  // Optionally set conn.version if you want specific API version:
  // conn.version = '60.0';

  return conn;
}

// Download latest ContentVersion VersionData as Buffer
async function downloadPdfBuffer(conn, contentDocumentId) {
  // Query latest content version id
  const qry = `SELECT Id, Title FROM ContentVersion WHERE ContentDocumentId='${contentDocumentId}' AND IsLatest=true LIMIT 1`;
  const qr = await conn.query(qry);
  if (!qr.records || qr.records.length === 0)
    throw new Error("No ContentVersion found for " + contentDocumentId);
  const cv = qr.records[0];
  const versionId = cv.Id;
  const url = `/services/data/v${conn.version}/sobjects/ContentVersion/${versionId}/VersionData`;
  // conn.request returns Buffer when responseType is set
  const res = await conn.request({
    method: "GET",
    url: url,
    encoding: null,
    headers: { Accept: "application/octet-stream" },
  });
  // jsforce returns a Buffer-like – ensure Buffer
  const buffer = Buffer.isBuffer(res) ? res : Buffer.from(res, "binary");
  return { buffer, title: cv.Title, versionId };
}

// Call Gemini (multipart). Assumes GEMINI_ENDPOINT accepts multipart 'instructions' and 'file' fields.
// If your Gemini endpoint needs different fields, adapt here.
async function callGeminiWithPdf(buffer, filename, prompt) {
  const form = new FormData();
  form.append("instructions", prompt);
  form.append("file", buffer, {
    filename: filename,
    contentType: "application/pdf",
  });

  const headers = Object.assign({}, form.getHeaders());
  if (GEMINI_API_KEY) headers["Authorization"] = `Bearer ${GEMINI_API_KEY}`;

  const res = await axios.post(GEMINI_ENDPOINT, form, {
    headers,
    maxContentLength: 200 * 1024 * 1024,
    maxBodyLength: 200 * 1024 * 1024,
    timeout: 120000,
  });
  return res.data; // assume JSON
}

// Insert claim + product line items into Salesforce via REST (using jsforce)
async function persistParsedToSalesforce(conn, parsed, linkedEntityId) {
  // parsed = { patientName, claimedAmount, approvedAmount, lineItems: [ ... ] }
  const claim = {
    Name: parsed.title || "Claim " + Date.now(),
    Patient_Name__c: parsed.patientName || null,
    Claimed_Amount__c: parsed.claimedAmount || null,
    Approved_Amount__c: parsed.approvedAmount || null,
    Opportunity__c: linkedEntityId || null, // optional field; adapt to your schema
  };
  const createdClaim = await conn.sobject("Insurance_Claim__c").create(claim);
  if (!createdClaim || !createdClaim.id)
    throw new Error("Failed to create claim: " + JSON.stringify(createdClaim));

  const claimId = createdClaim.id;

  // Build product line items
  const lineItems =
    parsed.lineItems && Array.isArray(parsed.lineItems) ? parsed.lineItems : [];
  const productSObjects = [];
  for (const li of lineItems) {
    const ip = {
      Insurance_Claim__c: claimId,
      Description__c: li.description || null,
      Line_Number__c: li.lineNumber ? parseInt(li.lineNumber) : null,
      Quantity__c: li.quantity ? parseFloat(li.quantity) : null,
      Unit__c: li.unit || null,
      RCV_Amount__c: li.rcv
        ? parseFloat(String(li.rcv).replace(/[^0-9\.\-]/g, ""))
        : null,
      Depreciation_Amount__c: li.depreciation
        ? parseFloat(String(li.depreciation).replace(/[^0-9\.\-]/g, ""))
        : null,
      ACV_Amount__c: li.acv
        ? parseFloat(String(li.acv).replace(/[^0-9\.\-]/g, ""))
        : null,
      TAX_Amount__c: li.tax
        ? parseFloat(String(li.tax).replace(/[^0-9\.\-]/g, ""))
        : null,
      OP_Amount__c: li.op
        ? parseFloat(String(li.op).replace(/[^0-9\.\-]/g, ""))
        : null,
      Section__c: li.section || null,
    };
    productSObjects.push(ip);
  }

  // Insert in batches (jsforce supports bulk create, but we'll use sobject.create in chunks)
  const BATCH = 50;
  for (let i = 0; i < productSObjects.length; i += BATCH) {
    const chunk = productSObjects.slice(i, i + BATCH);
    await conn.sobject("Insurance_Product__c").create(chunk);
  }

  return claimId;
}

// Helper to update PDF_Work_Item__c status
async function updateWorkItemStatus(conn, workItemId, status, errorDetail) {
  const s = { Id: workItemId, Status__c: status };
  if (errorDetail)
    s.Error_Detail__c =
      errorDetail.length > 32000
        ? errorDetail.substring(0, 32000)
        : errorDetail;
  await conn.sobject("PDF_Work_Item__c").update(s);
}

app.post("/process", async (req, res) => {
  try {
    // Basic auth: check header
    const authHeader = req.headers["authorization"];
    if (!authHeader || authHeader !== `Bearer ${WORKER_SECRET}`) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const items = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Expected array of work items" });
    }

    // Login once per request (reuse connection)
    const conn = await getSalesforceConnection();

    // Process items sequentially (one by one). For higher throughput you can parallelize carefully.
    for (const it of items) {
      const workItemId = it.workItemId;
      const contentDocumentId = it.contentDocumentId;
      const linkedEntityId = it.linkedEntityId;

      try {
        console.log("Processing", workItemId, contentDocumentId);

        // Download PDF
        const { buffer, title, versionId } = await downloadPdfBuffer(
          conn,
          contentDocumentId
        );

        // Compose prompt (you can refine prompt for strict JSON)
        const prompt =
          'Extract the following fields and return ONLY valid JSON: { "title":"", "patientName":"", "claimedAmount":"", "approvedAmount":"", "lineItems":[{"lineNumber":"","productName":"","description":"","quantity":"","unit":"","rcv":"","depreciation":"","acv":"","tax":"","op":"","section":""}] }';

        // Call Gemini (multipart)
        const geminiResp = await callGeminiWithPdf(
          buffer,
          title || "file.pdf",
          prompt
        );

        // geminiResp should be JSON. If not, try parsing string
        let parsed;
        if (typeof geminiResp === "object") {
          parsed = geminiResp;
        } else if (typeof geminiResp === "string") {
          try {
            parsed = JSON.parse(geminiResp);
          } catch (e) {
            throw new Error(
              "Gemini returned non-JSON or malformed JSON: " + e.message
            );
          }
        } else {
          throw new Error("Unexpected Gemini response type");
        }

        // Persist parsed JSON to Salesforce
        const claimId = await persistParsedToSalesforce(
          conn,
          parsed,
          linkedEntityId
        );

        // Update work item as completed and link to claim
        await updateWorkItemStatus(conn, workItemId, "Completed", null);
        try {
          await conn
            .sobject("PDF_Work_Item__c")
            .update({ Id: workItemId, Processed_Claim__c: claimId });
        } catch (e) {
          console.warn("Failed to update Processed_Claim__c: ", e.message);
        }

        console.log("Processed workItem", workItemId, "claim", claimId);
      } catch (errItem) {
        console.error(
          "Error processing item",
          workItemId,
          errItem && errItem.message ? errItem.message : errItem
        );
        try {
          await updateWorkItemStatus(
            conn,
            workItemId,
            "Error",
            errItem.message || String(errItem)
          );
        } catch (e) {
          console.error("Failed to update workItem error status", e.message);
        }
      }
    }

    return res.status(202).json({ status: "accepted", count: items.length });
  } catch (err) {
    console.error("Worker failure", err && err.stack ? err.stack : err);
    return res
      .status(500)
      .json({ error: err && err.message ? err.message : String(err) });
  }
});

app.get("/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

app.listen(PORT, () => console.log(`Worker ready on ${PORT}`));
