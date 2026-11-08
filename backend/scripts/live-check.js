import '../src/config/env.js';
import { checkGoogleSafeBrowsing } from '../src/services/threatIntel/gsbClient.js';
import { checkUrlhaus } from '../src/services/threatIntel/urlhausClient.js';

const targetUrls = [
  'https://testsafebrowsing.appspot.com/s/phishing.html',
  'https://example.com',
];

async function runLiveCheck() {
  for (const url of targetUrls) {
    const res = await checkGoogleSafeBrowsing({ url });
    console.log(`Provider: gsb | URL: ${url} | Status: ${res.status}`);
  }

  for (const url of targetUrls) {
    const res = await checkUrlhaus({ url });
    console.log(`Provider: urlhaus | URL: ${url} | Status: ${res.status}`);
  }
}

runLiveCheck().catch((err) => {
  console.error(`Provider error: ${err.message}`);
  process.exit(1);
});

