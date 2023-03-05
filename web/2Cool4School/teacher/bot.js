const express = require('express')
const puppeteer = require('puppeteer');

const app = express()
const port = 3000

const browser_options = {
	headless: true,
	args: [
		'--no-sandbox',
		'--disable-background-networking',
		'--disable-default-apps',
		'--disable-extensions',
		'--disable-gpu',
		'--disable-sync',
		'--disable-translate',
		'--hide-scrollbars',
		'--metrics-recording-only',
		'--mute-audio',
		'--no-first-run',
		'--safebrowsing-disable-auto-update',
		'--js-flags=--noexpose_wasm,--jitless'
	]
};

app.post('/read', async (req, res) => {
    const {id} = req.query
	if (!id) {
		return res.status(400).send('Missing id')
		console.log('Missing id')
	}
    await visitMessage(id)
	res.send('ok')
})

async function visitMessage(id){
    try {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();

        await page.goto(`http://grade.${process.env.BASEURL}/login`, {
			waitUntil: 'networkidle2',
			timeout: 10000
		});
        
        await page.type('#username', process.env.TEACHER_USERNAME)
        await page.type('#password', process.env.TEACHER_PASSWORD)
        await page.click('#submit')
        
        await page.waitForSelector('#root')
        
		await page.goto(`http://grade.${process.env.BASEURL}/grades/${id}`, {
			waitUntil: 'networkidle2',
			timeout: 10000
		});

		await new Promise(r => setTimeout(r, 2000));
		await browser.close();
    } catch(e) {
        console.log(e);
    }
}


app.listen(port, () => {})