document.addEventListener('DOMContentLoaded', () => {
    const formFlipper = document.querySelector('.form-flipper');
    const loginFormWrapper = document.getElementById('login-form-wrapper');
    const registerFormWrapper = document.getElementById('register-form-wrapper');
    const forgotFormWrapper = document.getElementById('forgot-form-wrapper');
    
    const showRegisterLink = document.getElementById('show-register');
    const showLoginLink = document.getElementById('show-login');
    const showForgotLink = document.getElementById('show-forgot');
    const backToLoginLink = document.getElementById('back-to-login');

    const allForms = [loginFormWrapper, registerFormWrapper, forgotFormWrapper];

    function showForm(activeForm) {
        allForms.forEach(form => {
            if (form === activeForm) {
                form.classList.add('active');
            } else {
                form.classList.remove('active');
            }
        });
        setFlipperHeight();
    }

    function setFlipperHeight() {
        // Da un respiro al navegador para que actualice el DOM antes de medir la altura
        setTimeout(() => {
            const activeForm = document.querySelector('.form-wrapper.active');
            if (activeForm) {
                // Medimos la altura total del contenido del formulario activo
                formFlipper.style.height = `${activeForm.scrollHeight}px`;
            }
        }, 50); 
    }

    // Asignar eventos a los enlaces
    showRegisterLink.addEventListener('click', (e) => { e.preventDefault(); showForm(registerFormWrapper); });
    showLoginLink.addEventListener('click', (e) => { e.preventDefault(); showForm(loginFormWrapper); });
    showForgotLink.addEventListener('click', (e) => { e.preventDefault(); showForm(forgotFormWrapper); });
    backToLoginLink.addEventListener('click', (e) => { e.preventDefault(); showForm(loginFormWrapper); });

    // --- Lógica de visibilidad de contraseña (sin cambios) ---
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

    // --- Lógica de fuerza de contraseña (sin cambios) ---
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
        if (score <= 1) strengthFill.style.backgroundColor = 'var(--strength-weak)';
        else if (score <= 3) strengthFill.style.backgroundColor = 'var(--strength-medium)';
        else strengthFill.style.backgroundColor = 'var(--strength-strong)';
        registerSubmitButton.disabled = score < 4;
        setFlipperHeight(); // Reajusta la altura mientras escribes por si aparece la política
    });
    
    // --- Lógica de envío de formularios (sin cambios) ---
    const registerForm = document.getElementById('register-form');
    const registerMessageArea = document.getElementById('register-message-area');
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        registerMessageArea.className = 'message-area';
        const name = document.getElementById('register-name').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        if (password !== confirmPassword) {
            displayMessage('Las contraseñas no coinciden.', 'error', registerMessageArea);
            return;
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
                registerForm.reset();
                Object.values(policyItems).forEach(item => item.classList.remove('valid'));
                strengthFill.style.width = '0%';
                registerSubmitButton.disabled = true;
                setFlipperHeight();
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
    
    const forgotForm = document.getElementById('forgot-form');
    const forgotMessageArea = document.getElementById('forgot-message-area');
    forgotForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        forgotMessageArea.className = 'message-area';
        const email = document.getElementById('forgot-email').value;
        try {
            const response = await fetch('/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email }),
            });
            const result = await response.json();
            displayMessage(result.message, 'success', forgotMessageArea);
            forgotForm.reset();
        } catch (error) {
            displayMessage('Error de conexión con el servidor.', 'error', forgotMessageArea);
        }
    });

    function displayMessage(message, type, area) {
        area.textContent = message;
        area.className = `message-area ${type}`;
    }
    
    // Llamada inicial para asegurar que el contenedor tiene la altura correcta
    setFlipperHeight();
});