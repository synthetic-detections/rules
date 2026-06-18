// Legitimate axios HTTP client usage — should NOT trigger
const axios = require('axios');

async function fetchData() {
    const response = await axios.get('https://api.example.com/data', {
        headers: { 'User-Agent': 'MyApp/1.0' }
    });
    return response.data;
}

async function postData(payload) {
    const response = await axios.post('https://api.example.com/submit', payload);
    console.log('Status:', response.status);
}

fetchData().then(console.log);
