document.addEventListener('DOMContentLoaded', () => {
    // --- LÓGICA DE GIRO Y AJUSTE DE ALTURA ---
    const loginContainer = document.querySelector('.login-container');
    const formFlipper = document.querySelector('.form-flipper');
    const loginFormWrapper = document.getElementById('login-form-wrapper');
    const registerFormWrapper = document.getElementById('register-form-wrapper');
    const showRegisterLink = document.getElementById('show-register');
    const showLoginLink = document.getElementById('show-login');
    function setFlipperHeight() {
        const loginHeight = loginFormWrapper.scrollHeight;
        const registerHeight = registerFormWrapper.scrollHeight;
        if (loginContainer.classList.contains('is-flipped')) {
            formFlipper.style.height = `${registerHeight}px`;
        } else {
            formFlipper.style.height = `${loginHeight}px`;
        }
    }
    setFlipperHeight();
    showRegisterLink.addEventListener('click', (e) => { e.preventDefault(); loginContainer.classList.add('is-flipped'); setFlipperHeight(); });
    showLoginLink.addEventListener('click', (e) => { e.preventDefault(); loginContainer.classList.remove('is-flipped'); setFlipperHeight(); });

    // --- LÓGICA DE VISIBILIDAD DE CONTRASEÑA ---
    const passwordToggles = document.querySelectorAll('.password-toggle');
    passwordToggles.forEach(toggle => {
        toggle.addEventListener('click', () => {
            const passwordInput = toggle.previousElementSibling;
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            toggle.classList.toggle('fa-eye');
            toggle.classList.toggle('fa-eye-slash');
        });
    });

    // --- LÓGICA DE FUERZA DE CONTRASEÑA ---
    const registerPasswordInput = document.getElementById('register-password');
    const strengthFill = document.getElementById('strength-fill');
    const policyItems = {
        length: document.getElementById('policy-length'),
        uppercase: document.getElementById('policy-uppercase'),
        number: document.getElementById('policy-number'),
        special: document.getElementById('policy-special'),
    };
    const registerSubmitButton = document.getElementById('register-submit-button');

    registerPasswordInput.addEventListener('input', () => {
        const password = registerPasswordInput.value;
        let score = 0;
        const validations = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password),
        };

        Object.keys(validations).forEach(key => {
            if (validations[key]) {
                policyItems[key].classList.add('valid');
                score++;
            } else {
                policyItems[key].classList.remove('valid');
            }
        });
        
        const strengthPercentage = (score / 4) * 100;
        strengthFill.style.width = `${strengthPercentage}%`;
        if (score <= 1) {
            strengthFill.style.backgroundColor = 'var(--strength-weak)';
        } else if (score <= 3) {
            strengthFill.style.backgroundColor = 'var(--strength-medium)';
        } else {
            strengthFill.style.backgroundColor = 'var(--strength-strong)';
        }
        
        registerSubmitButton.disabled = score < 4;
        setFlipperHeight();
    });

    // --- LÓGICA DE FORMULARIOS ---
    const registerForm = document.getElementById('register-form');
    const registerMessageArea = document.getElementById('register-message-area');
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        registerMessageArea.className = 'message-area';
        const name = document.getElementById('register-name').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        // Obtenemos el valor del campo de confirmación
        const confirmPassword = document.getElementById('register-confirm-password').value;

        // **VALIDACIÓN DE CONFIRMACIÓN DE CONTRASEÑA**
        if (password !== confirmPassword) {
            displayMessage('Las contraseñas no coinciden.', 'error', registerMessageArea);
            return; // Detenemos el envío del formulario
        }

        try {
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, password }),
            });
            const result = await response.json();
            if (response.ok) {
                displayMessage(result.message, 'success', registerMessageArea);
                setTimeout(() => {
                    loginContainer.classList.remove('is-flipped'); setFlipperHeight();
                    registerForm.reset();
                    Object.values(policyItems).forEach(item => item.classList.remove('valid'));
                    strengthFill.style.width = '0%';
                    registerSubmitButton.disabled = true;
                    displayMessage('Registro exitoso. Ahora puedes iniciar sesión.', 'success', document.getElementById('login-message-area'));
                }, 2000);
            } else {
                displayMessage(result.error, 'error', registerMessageArea);
            }
        } catch (error) {
            displayMessage('Error de conexión con el servidor.', 'error', registerMessageArea);
        }
    });

    const loginForm = document.getElementById('login-form');
    const loginMessageArea = document.getElementById('login-message-area');
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginMessageArea.className = 'message-area';
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });
            const result = await response.json();
            if (response.ok) {
                window.location.href = result.redirect_url;
            } else {
                displayMessage(result.error, 'error', loginMessageArea);
            }
        } catch (error) {
            displayMessage('Error de conexión con el servidor.', 'error', loginMessageArea);
        }
    });
});

function displayMessage(message, type, area) {
    area.textContent = message;
    area.className = `message-area ${type}`;
}