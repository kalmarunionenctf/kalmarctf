setTimeout(() => {
    console.log("Too slow!");
    process.exit();
}, 15000);

function generatePhrase(words) {
    const phrase = [];
    const redacted = [];
    for (let i = 0; i < 12; i++) {
        const word = words[Math.floor(Math.random()*words.length)];
        phrase.push(word);
        if (i < 5)
            redacted.push(word[0] + "****");
        else
            redacted.push("*****");
    }
    return [phrase.join(" "), redacted.join(" ")];
}

const fs = require("fs");
const readline = require("readline");
const wordlist = fs.readFileSync("words.txt", "utf8").trim().split("\n");

for (let i = 0; i < 13371337; i++)
    Math.random();

const [phrase, redactedPhrase] = generatePhrase(wordlist);

console.log("Welcome to the #crypto-gang admin panel!")
console.log();
console.log("Please enter the seed phrase for your crypto-wallet to log in.")
console.log(`(hint: ${redactedPhrase})`);

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
rl.question("> ", (answer) => {
    if (answer === phrase)
        console.log(fs.readFileSync("flag.txt", "utf8"));
    else
        console.log("Nope!"); 
    process.exit();
});
