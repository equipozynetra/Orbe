document.addEventListener('DOMContentLoaded', function() {
    
    // --- 1. VISIBILIDAD DE CONTRASEÑA (OJO) ---
    const toggles = document.querySelectorAll('.password-toggle');
    toggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const input = this.previousElementSibling;
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            this.classList.toggle('visible');
        });
    });

    // --- 2. MEDIDOR DE FUERZA DE CONTRASEÑA ---
    const passInput = document.getElementById('pass-input');
    const strengthBar = document.getElementById('strength-bar-fill');
    const strengthText = document.getElementById('strength-text');

    if (passInput && strengthBar) {
        passInput.addEventListener('input', function() {
            const val = passInput.value;
            let strength = 0;
            
            if (val.length > 5) strength += 25;
            if (val.length > 8) strength += 25;
            if (/[A-Z]/.test(val)) strength += 25;
            if (/[0-9]/.test(val)) strength += 25;

            strengthBar.style.width = strength + '%';
            
            if (strength < 50) {
                strengthBar.style.backgroundColor = '#ff3b30'; // Rojo
                strengthText.innerText = "Nivel de seguridad: Crítico";
            } else if (strength < 75) {
                strengthBar.style.backgroundColor = '#ffcc00'; // Amarillo
                strengthText.innerText = "Nivel de seguridad: Moderado";
            } else {
                strengthBar.style.backgroundColor = '#00ff9d'; // Verde
                strengthText.innerText = "Nivel de seguridad: Óptimo";
            }
        });
    }

    // --- 3. PUZZLE ORBE (Slider de Sincronización) ---
    const slider = document.getElementById('puzzle-slider');
    const handle = document.getElementById('puzzle-handle');
    const overlay = document.getElementById('puzzle-overlay');
    const submitBtn = document.getElementById('submit-btn');
    const puzzleStatus = document.getElementById('puzzle-status');
    let isDragging = false;

    if (slider && handle) {
        handle.addEventListener('mousedown', startDrag);
        document.addEventListener('mouseup', endDrag);
        document.addEventListener('mousemove', drag);

        function startDrag(e) { isDragging = true; }

        function drag(e) {
            if (!isDragging) return;
            let containerRect = slider.getBoundingClientRect();
            let x = e.clientX - containerRect.left;
            
            // Limites
            if (x < 0) x = 0;
            if (x > containerRect.width - handle.offsetWidth) x = containerRect.width - handle.offsetWidth;

            handle.style.left = x + 'px';
            overlay.style.width = x + 'px';

            // Verificar si llegó al final (con un margen de error)
            if (x >= (containerRect.width - handle.offsetWidth - 5)) {
                unlockSystem();
            }
        }

        function endDrag() {
            if (!isDragging) return;
            isDragging = false;
            // Si no está desbloqueado, volver al inicio
            if (!submitBtn.disabled) return;
            
            handle.style.left = '0px';
            overlay.style.width = '0px';
        }

        function unlockSystem() {
            isDragging = false;
            handle.style.left = (slider.offsetWidth - handle.offsetWidth) + 'px';
            slider.classList.add('unlocked');
            puzzleStatus.innerText = "Sincronización Completa";
            puzzleStatus.style.color = "#00ff9d";
            
            // Habilitar botón de registro
            submitBtn.disabled = false;
            submitBtn.classList.remove('disabled');
            
            // Campo oculto para decirle al servidor que se resolvió
            document.getElementById('captcha-solved').value = "true";
        }
    }
});