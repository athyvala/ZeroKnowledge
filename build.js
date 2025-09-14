const fs = require('fs');
require('dotenv').config(); // npm install dotenv

const filesToProcess = [
  'extension/content-script.js',
  'extension/ai-filter.js' // If still using
];

filesToProcess.forEach(filePath => {
  if (fs.existsSync(filePath)) {
    let content = fs.readFileSync(filePath, 'utf8');
    
    // Replace placeholder with actual key for local testing
    content = content.replace(
      /'HUGGING_FACE_API_KEY_PLACEHOLDER'/g,
      JSON.stringify(process.env.HUGGING_FACE_API_KEY || '')
    );
    
    fs.writeFileSync(filePath, content);
    console.log(`✅ Built ${filePath} with secure key injection`);
  }
});
