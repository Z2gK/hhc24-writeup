# Prologue

Here are the solutions to challenges in Prologue.

## First Terminal

This challenge is meant as an orientation. A terminal is launched when the challenge is started. Simply follow the on-screen instructions and enter **answer**. There is no Gold or Silver award.

![Enter the answer](files/Prologue/firstterminal1.png)

## Elf Connect

Elf Connect is based on the New York Times [Connections](https://www.nytimes.com/games/connections) game. 16 words are displayed in a grid, and the objective is to group the words into groups of 4. Each group of word should share a common theme. For this challenge, there are 4 rounds.

![Elf Connect Round 1](files/Prologue/elfconnect1.png)

**FOR SILVER AWARD**, one just needs group the words correctly in all 4 rounds.This can be rather time consuming and would involve a fair bit of guesswork, especially where certain words are unfamiliar or quite technical.

The solution can be found in the Javascript code for this challenge. Open "Developer mode" in the browser (Firefox is used here, but other mainstream browsers should work similarly) and navigate to the code for this game. This can be found in the "Debugger" tab for Firefox.

![Answer to Connections](files/Prologue/elfconnect2.png)

The wordsets and solution can be found from line 60 onwards. The wordsets for each round are found in the `wordSets` dictionary, while the array indices for the correct word groups are in the `correctSets` array.

Word list for each round in `wordSets`:

```
const wordSets = {
	1: ["Tinsel", "Sleigh", "Belafonte", "Bag", "Comet", "Garland", "Jingle Bells", "Mittens", "Vixen", "Gifts", "Star", "Crosby", "White Christmas", "Prancer", "Lights", "Blitzen"],
	2: ["Nmap", "burp", "Frida", "OWASP Zap", "Metasploit", "netcat", "Cycript", "Nikto", "Cobalt Strike", "wfuzz", "Wireshark", "AppMon", "apktool", "HAVOC", "Nessus", "Empire"],
	3: ["AES", "WEP", "Symmetric", "WPA2", "Caesar", "RSA", "Asymmetric", "TKIP", "One-time Pad", "LEAP", "Blowfish", "hash", "hybrid", "Ottendorf", "3DES", "Scytale"],
	4: ["IGMP", "TLS", "Ethernet", "SSL", "HTTP", "IPX", "PPP", "IPSec", "FTP", "SSH", "IP", "IEEE 802.11", "ARP", "SMTP", "ICMP", "DNS"]
};
```

The `correctSets` array:

```
let correctSets = [
	[0, 5, 10, 14], // Set 1
	[1, 3, 7, 9],   // Set 2
	[2, 6, 11, 12], // Set 3
	[4, 8, 13, 15]  // Set 4
];

```

A correct word group for Round 1 can be found at array indices 0, 5, 10 and 14. This corresponds to the words "Tinsel", "Garland", "Star" and "Lights". Another correct group is at array indices 1, 3, 7 and 9, which map to the words "Sleigh", "Bag", "Mittens" and "Gifts". The same goes for the other word sets.

**FOR GOLD AWARD**, one can refer to the following hint from Angel Candysalt.

> WOW! A high score of 50,000 points! That’s way beyond the limit! With only four rounds and a max of 400 points per round, the top possible score should be 1,600 points. So, how did someone get to 50,000? Something unusual must be happening!
>
> If you're curious, you might want to check under the hood. Try opening the browser's developer tools console and looking around—there might even be a variable named 'score' that could give you some insights. Sometimes, games hold secrets for those who dig a little deeper. Give it a shot and see what you can discover!

The script increments and checks the current score near line 250. In Firefox developer mode, set a breakpoint at the `scoreText.setText()` function and play one round of the game as usual. Once done with the round, execution will stop at the breakpoint. Switch to the "Console" tab of developer mode and increment the `score` variable beyond 50000 using a statement such as `score += 60000`. Then continue execution so that the condition for `score > 50000` is triggered for the Gold award.

![Code for score checking](files/Prologue/elfconnect3.png)

## Elf Minder 9000

*TBC*

