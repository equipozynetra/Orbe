document.addEventListener('DOMContentLoaded', () => {
    const userInput = document.getElementById('user-input');
    const sendButton = document.getElementById('send-button');

    // --- LÓGICA PARA EL TEXTAREA DE TAMAÑO AUTOMÁTICO ---
    
    // Función para ajustar la altura del textarea
    const adjustTextareaHeight = () => {
        userInput.style.height = 'auto'; // Resetea la altura para recalcular
        userInput.style.height = `${userInput.scrollHeight}px`; // Ajusta a la altura del contenido
    };

    // Función para habilitar/deshabilitar el botón de enviar
    const toggleSendButton = () => {
        // Si el texto (sin espacios en blanco) no está vacío, habilita el botón
        if (userInput.value.trim() !== '') {
            sendButton.disabled = false;
        } else {
            sendButton.disabled = true;
        }
    };

    // Añadir los 'event listeners' al textarea
    userInput.addEventListener('input', () => {
        adjustTextareaHeight();
        toggleSendButton();
    });

    // Llamada inicial para asegurar que todo esté correcto al cargar la página
    adjustTextareaHeight();
    toggleSendButton();


    // --- PRÓXIMAMENTE: Lógica para enviar el mensaje ---
    const chatForm = document.getElementById('chat-form');
    if (chatForm) { // Comprobamos que el formulario existe
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault(); // Evita que la página se recargue
            
            const messageText = userInput.value.trim();
            if (messageText) {
                console.log('Mensaje enviado:', messageText); // Por ahora, solo lo mostramos en consola
                
                // Aquí es donde añadiremos la lógica para mostrar el mensaje en la pantalla
                
                // Limpiar el textarea y reajustar su altura
                userInput.value = '';
                adjustTextareaHeight();
                toggleSendButton();
            }
        });
    }

});