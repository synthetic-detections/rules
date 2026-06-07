// Benign baseline: a normal cross-platform WebView bridge using the
// standard postMessage API. No campaign anchors of any kind.

window.addEventListener('message', (event) => {
    if (event.data.type === 'theme') {
        document.body.dataset.theme = event.data.value;
    }
});

document.getElementById('refresh').addEventListener('click', () => {
    window.parent.postMessage({type: 'refresh'}, '*');
});
