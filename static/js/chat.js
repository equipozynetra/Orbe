/* --- LÓGICA DEL MODAL (Global) --- */
/* Estas funciones deben estar fuera del EventListener para que el HTML las encuentre */

function openModal(deleteUrl) {
    const modal = document.getElementById('deleteModal');
    const confirmBtn = document.getElementById('confirmDeleteBtn');
    
    // Asignamos la URL de borrado al botón de confirmación
    if (confirmBtn) confirmBtn.href = deleteUrl;
    
    // Mostramos el modal
    if (modal) modal.style.display = 'flex';
}

function closeModal() {
    const modal = document.getElementById('deleteModal');
    if (modal) modal.style.display = 'none';
}

// Cerrar si se hace clic fuera del contenido del modal
window.onclick = function(event) {
    const modal = document.getElementById('deleteModal');
    if (event.target == modal) {
        closeModal();
    }
}

/* --- LÓGICA DEL CHAT --- */
document.addEventListener('DOMContentLoaded', function() {
    
    const form = document.getElementById('chat-form');
    const input = document.getElementById('user-input');
    const messagesBox = document.getElementById('messages-box');

    // Scroll al final al cargar la página (para ver los últimos mensajes)
    if (messagesBox) {
        scrollToBottom();
    }

    // Solo activamos la lógica si el formulario existe (si hay un chat activo)
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault(); // Evitar recarga de página
            
            const text = input.value.trim();
            if (!text) return;

            // 1. Agregar mensaje del Usuario visualmente
            addMessage(text, 'user');
            input.value = ''; // Limpiar input

            // 2. Simular "Escribiendo..." y respuesta de Orbe
            // (Aquí conectaríamos con la API real más adelante)
            showTypingIndicator();
            
            setTimeout(() => {
                removeTypingIndicator();
                // Respuesta simulada temporal
                addMessage("He recibido tu instrucción: " + text + ". Procesando en el núcleo...", 'orbe');
            }, 1500); // 1.5 segundos de "pensamiento"
        });
    }

    // Función para agregar mensajes al DOM
    function addMessage(text, sender) {
        if (!messagesBox) return;

        const div = document.createElement('div');
        div.classList.add('message', sender);
        
        // Estructura HTML dependiendo de quién envía
        if (sender === 'user') {
            div.innerHTML = `
                <div class="msg-content"><p>${text}</p></div>
                <div class="msg-avatar"><div class="user-mini">YO</div></div>
            `;
        } else {
            div.innerHTML = `
                <div class="msg-avatar"><div class="orb-mini"></div></div>
                <div class="msg-content"><p>${text}</p></div>
            `;
        }
        
        messagesBox.appendChild(div);
        scrollToBottom();
    }

    // Función para bajar el scroll
    function scrollToBottom() {
        if (messagesBox) {
            messagesBox.scrollTop = messagesBox.scrollHeight;
        }
    }

    // Mostrar indicador "..."
    function showTypingIndicator() {
        if (!messagesBox) return;
        
        const div = document.createElement('div');
        div.id = 'typing-indicator';
        div.classList.add('message', 'orbe');
        div.innerHTML = `
            <div class="msg-avatar"><div class="orb-mini"></div></div>
            <div class="msg-content" style="color: #888; font-style: italic;">Analizando...</div>
        `;
        messagesBox.appendChild(div);
        scrollToBottom();
    }

    // Quitar indicador "..."
    function removeTypingIndicator() {
        const indicator = document.getElementById('typing-indicator');
        if (indicator) indicator.remove();
    }
});