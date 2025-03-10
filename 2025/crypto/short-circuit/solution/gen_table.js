function generatePhrase(words) {
    // reduced version of the main challenge's function
    // just to save space/mem/go-faster
    const indexes = [];
    const letters = [];
    for (let i = 0; i < 12; i++) {
        const wordIndex = Math.floor(Math.random()*words.length);
        indexes.push(wordIndex.toString());
        if (i < 5)
            letters.push(words[wordIndex][0]);
    }
    return [indexes.join(","), letters.join("")];
}

const fs = require("fs");
const wordlist = fs.readFileSync("words.txt", "utf8").trim().split("\n");

// to get right randomness offset
for (let i = 0; i < 13371337; i++)
    Math.random();

// make damn sure we get into the NaN loop
// slow but whatever, this only runs once
for (let i = 0; i < 100000000*62; i++)
    Math.random();

const s = fs.createWriteStream("table.txt", {"encoding": "utf-8"});

const seenLetters = {};

// https://issues.chromium.org/issues/42211416#comment2
for (let i = 0; i < 682927953/62; i++) {
    if (i % 10000 == 0) {
        console.log(i);
    }
    const [indexes, letters] = generatePhrase(wordlist);
    if (!seenLetters[letters]) {
        s.write(`${letters}:${indexes}\n`);
        seenLetters[letters] = true;
    }

    // we've spent 12 rolls of the 62-roll stride, get back on track
    for (let j = 0; j < 62-12; j++) Math.random();
}
s.close();