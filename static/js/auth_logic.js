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

    // --- 3. PUZZLE ORBE (Compatibilidad Móvil + PC) ---
    const slider = document.getElementById('puzzle-slider');
    const handle = document.getElementById('puzzle-handle');
    const overlay = document.getElementById('puzzle-overlay');
    const submitBtn = document.getElementById('submit-btn');
    const puzzleStatus = document.getElementById('puzzle-status');
    const hiddenInput = document.getElementById('captcha-solved');
    
    let isDragging = false;

    if (slider && handle) {
        // EVENTOS RATÓN (PC)
        handle.addEventListener('mousedown', startDrag);
        document.addEventListener('mousemove', drag);
        document.addEventListener('mouseup', endDrag);

        // EVENTOS TÁCTILES (MÓVIL)
        handle.addEventListener('touchstart', startDrag, { passive: false });
        document.addEventListener('touchmove', drag, { passive: false });
        document.addEventListener('touchend', endDrag);

        function startDrag(e) {
            // Solo iniciamos si el botón aún no está habilitado
            if (submitBtn.disabled) {
                isDragging = true;
            }
        }

        function drag(e) {
            if (!isDragging) return;
            
            // Evitar que la pantalla se mueva (scroll) mientras arrastramos el slider en móvil
            if(e.type === 'touchmove') {
                e.preventDefault(); 
            }

            // Obtener la posición X (Mouse o Dedo)
            let clientX;
            if (e.type === 'touchmove') {
                clientX = e.touches[0].clientX;
            } else {
                clientX = e.clientX;
            }

            let containerRect = slider.getBoundingClientRect();
            let x = clientX - containerRect.left;
            
            // Límites del slider
            if (x < 0) x = 0;
            if (x > containerRect.width - handle.offsetWidth) x = containerRect.width - handle.offsetWidth;

            // Actualizar visualmente
            handle.style.left = x + 'px';
            overlay.style.width = x + 'px';

            // Verificar si llegó al final
            if (x >= (containerRect.width - handle.offsetWidth - 5)) {
                unlockSystem();
            }
        }

        function endDrag() {
            if (!isDragging) return;
            isDragging = false;
            
            // Si no se completó, volver al inicio (efecto rebote)
            if (submitBtn.disabled) {
                handle.style.left = '0px';
                overlay.style.width = '0px';
                handle.style.transition = 'left 0.3s ease';
                overlay.style.transition = 'width 0.3s ease';
                
                // Quitar transición después de la animación para que el drag sea fluido
                setTimeout(() => {
                    handle.style.transition = '';
                    overlay.style.transition = '';
                }, 300);
            }
        }

        function unlockSystem() {
            isDragging = false;
            
            // Fijar al final
            handle.style.left = (slider.offsetWidth - handle.offsetWidth) + 'px';
            overlay.style.width = '100%';
            
            // Cambios visuales
            slider.classList.add('unlocked');
            puzzleStatus.innerText = "Sincronización Completa";
            puzzleStatus.style.color = "#00ff9d";
            
            // Habilitar botón de registro
            submitBtn.disabled = false;
            submitBtn.classList.remove('disabled');
            
            // Decirle al servidor que somos humanos
            if(hiddenInput) hiddenInput.value = "true";
        }
    }
});