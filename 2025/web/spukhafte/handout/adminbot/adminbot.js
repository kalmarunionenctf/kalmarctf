const express = require('express');
const puppeteer = require('puppeteer');
const app = express();

const FLAG = process.env.FLAG || 'kalmar{test_flag}';
const NOTE_DOMAIN = process.env.NOTE_DOMAIN || 'https://notes-spukhafte.chal-kalmarc.tf/';
const XSS_DOMAIN = process.env.XSS_DOMAIN || 'https://xss-spukhafte.chal-kalmarc.tf/';

app.use(express.json());

function sleep(ms) {
    return new Promise(res => setTimeout(res, ms));
}

async function visitUrl(url) {
  const browser = await puppeteer.launch({
    headless: true,
    args: [
      // this is not a pwn challenge, please don't rce us
      '--disable-extensions',
      '--disable-gpu',
      '--disable-software-rasterizer',
      '--js-flags=--noexpose_wasm,--jitless',
      '--no-sandbox',

      '--ignore-certificate-errors', // (not there on remote, just for local testing)
    ]
  });

  try {
    const page = await browser.newPage();

    await page.goto(NOTE_DOMAIN, {
      waitUntil: 'networkidle0',
    });

    // hmm... i think i'll put my flag here.
    await page.evaluate((flag) => {
      const noteInput = document.getElementById('noteInput');
      if (noteInput) {
        noteInput.value = flag;

        const saveButton = document.querySelector('button');
        if (saveButton) {
          saveButton.click();
        }
      }
    }, FLAG);

    await sleep(1000);

    // whew... time to go look at my favorite ctf team's website :)
    await page.goto("https://kalmarunionen.dk");

    await sleep(1000);

    // now visit user page
    const page2 = await browser.newPage();
    await page2.goto(url, {waitUntil: []});

    await sleep(5000);
  } catch (err) {
    console.error('Error visiting page:', err);
  } finally {
    await browser.close();
  }
}

app.post('/report', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string' || !url.startsWith(XSS_DOMAIN)) {
    return res.status(400).json({ error: `Invalid URL. Url should be a string and start with ${XSS_DOMAIN}` });
  }

  try {
    await visitUrl(url);
    res.json({ success: true });
  } catch (err) {
    console.error('Error on /report', err);
    res.status(500).json({ error: 'Failed to visit URL' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Adminbot listening on port ${PORT}`);
});