const fs = require('fs');
require('dotenv').config();

// Read the content script template
let contentScript = fs.readFileSync('content-script-template.js', 'utf8');

// Replace the placeholder with the actual API key
contentScript = contentScript.replace(
    'HUGGING_FACE_API_KEY_PLACEHOLDER', 
    process.env.HUGGING_FACE_API_KEY
);

// Write the final content script
fs.writeFileSync('content-script.js', contentScript);

console.log('✅ Extension built with API key injected');
