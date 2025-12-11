document.addEventListener('DOMContentLoaded', function() {
    
    // 1. RELOJ DIGITAL
    function updateClock() {
        const now = new Date();
        document.getElementById('digital-clock').innerText = now.toLocaleTimeString('es-ES');
    }
    setInterval(updateClock, 1000);
    updateClock();

    // 2. EFECTO DE ESCRITURA
    const textElement = document.getElementById('typing-text');
    if (textElement) {
        const text = "Conexión con el núcleo establecida. Sistemas operativos.";
        let i = 0;
        function typeWriter() {
            if (i < text.length) {
                textElement.innerHTML += text.charAt(i);
                i++;
                setTimeout(typeWriter, 30);
            }
        }
        typeWriter();
    }

    // 3. ESTADO DEL NÚCLEO EN TIEMPO REAL (Simulación)
    const cpuBar = document.getElementById('cpu-fill');
    const ramBar = document.getElementById('ram-fill');
    const cpuText = document.getElementById('cpu-text');
    const ramText = document.getElementById('ram-text');

    function fetchStatus() {
        // Llamamos a la API interna de Flask
        fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                if (cpuBar) {
                    cpuBar.style.width = data.cpu + '%';
                    // Cambiar color si está muy alto
                    cpuBar.style.backgroundColor = data.cpu > 80 ? '#ff003c' : '#00ff9d';
                }
                if (ramBar) ramBar.style.width = data.ram + '%';
                
                // Actualizar textos si existen
                if(cpuText) cpuText.innerText = data.cpu + '%';
                if(ramText) ramText.innerText = data.ram + '%';
            })
            .catch(err => console.log("Error status:", err));
    }

    // Actualizar cada 2 segundos
    if (cpuBar || ramBar) {
        setInterval(fetchStatus, 2000);
        fetchStatus(); // Primera llamada
    }
});