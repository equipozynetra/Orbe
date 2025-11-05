document.addEventListener('DOMContentLoaded', () => {
    // --- REFERENCIAS A ELEMENTOS DEL DOM ---
    const userInput = document.getElementById('user-input');
    const sendButton = document.getElementById('send-button');
    const newChatButton = document.querySelector('.new-chat-button');
    const mainContent = document.querySelector('.main-content');
    const chatHistory = document.querySelector('.chat-history ul');
    const notificationContainer = document.getElementById('notification-container');
    const chatForm = document.getElementById('chat-form');

    // --- LÓGICA DE NOTIFICACIONES PERSONALIZADAS ---
    const showNotification = (message, type = 'info', options = {}) => {
        const toast = document.createElement('div');
        toast.className = `toast toast--${type}`;
        
        const icons = {
            success: '<i class="ph-bold ph-check-circle"></i>',
            info: '<i class="ph-bold ph-info"></i>',
            error: '<i class="ph-bold ph-warning-circle"></i>',
            confirm: '<i class="ph-bold ph-question"></i>'
        };

        let buttonsHtml = '';
        if (type === 'confirm') {
            buttonsHtml = `
                <div class="toast-buttons">
                    <button class="toast-button cancel">No</button>
                    <button class="toast-button confirm">Sí</button>
                </div>
            `;
        }
        
        toast.innerHTML = `<span class="toast-icon">${icons[type]}</span> ${message} ${buttonsHtml}`;
        notificationContainer.appendChild(toast);

        if (type === 'confirm') {
            toast.querySelector('.toast-button.confirm').addEventListener('click', () => {
                if (options.onConfirm) options.onConfirm();
                toast.remove();
            });
            toast.querySelector('.toast-button.cancel').addEventListener('click', () => toast.remove());
        } else {
            // La notificación se cierra sola después de 3 segundos
            setTimeout(() => toast.classList.add('fade-out'), 3000);
            setTimeout(() => toast.remove(), 3500); // 3.5s para dar tiempo a la animación de salida
        }
    };

    // --- LÓGICA PARA EL TEXTAREA DE TAMAÑO AUTOMÁTICO Y BOTÓN DE ENVÍO ---
    const adjustTextareaHeight = () => {
        if (!userInput) return;
        userInput.style.height = 'auto';
        userInput.style.height = `${userInput.scrollHeight}px`;
    };
    const toggleSendButton = () => {
        if (!userInput || !sendButton) return;
        sendButton.disabled = userInput.value.trim() === '';
    };

    if (userInput) {
        userInput.addEventListener('input', () => {
            adjustTextareaHeight();
            toggleSendButton();
        });
    }
    // Llamadas iniciales para asegurar el estado correcto al cargar
    adjustTextareaHeight();
    toggleSendButton();

    // --- LÓGICA PARA CREAR UN NUEVO CHAT CON ANIMACIÓN RÁPIDA ---
    if (newChatButton) {
        newChatButton.addEventListener('click', async () => {
            // Activa la animación de fundido de forma instantánea
            if (mainContent) {
                mainContent.style.animation = 'none';
                void mainContent.offsetWidth; // Truco para forzar el reinicio de la animación
                mainContent.style.animation = 'fadeInMain 0.3s ease-out';
            }
            
            // Realiza la petición al backend inmediatamente, sin retardos
            try {
                const response = await fetch('/api/chats', { method: 'POST' });
                if (response.ok) {
                    const result = await response.json();
                    window.location.href = `/chat/${result.new_chat_id}`;
                } else {
                    const error = await response.json();
                    showNotification(error.error, 'error'); // Muestra la notificación de error
                }
            } catch (error) {
                showNotification('Error de conexión al crear el chat.', 'error');
            }
        });
    }

    // --- LÓGICA PARA ELIMINAR UN CHAT CON NOTIFICACIÓN DE CONFIRMACIÓN ---
    if (chatHistory) {
        chatHistory.addEventListener('click', (e) => {
            const deleteButton = e.target.closest('.delete-chat-button');
            if (!deleteButton) return;
            
            e.preventDefault();
            e.stopPropagation();
            
            const chatItem = deleteButton.closest('.history-item');
            const chatId = chatItem.dataset.chatId;

            showNotification('¿Eliminar este chat?', 'confirm', {
                onConfirm: async () => {
                    try {
                        const response = await fetch(`/api/chats/${chatId}`, { method: 'DELETE' });
                        if (response.ok) {
                            showNotification('Chat eliminado con éxito.', 'success');
                            if (chatItem.classList.contains('active')) {
                                // Si borramos el chat activo, redirigimos a la página de chat principal
                                window.location.href = '/chat';
                            } else {
                                // Si no, simplemente lo quitamos de la lista
                                chatItem.remove();
                                // Aquí se podría actualizar el contador de chats si se quisiera
                            }
                        } else {
                            const error = await response.json();
                            showNotification(error.error, 'error');
                        }
                    } catch (error) {
                        showNotification('Error de conexión al eliminar.', 'error');
                    }
                }
            });
        });
    }
    
    // --- LÓGICA PARA ENVIAR EL MENSAJE (AÚN SIN CONEXIÓN A LA IA) ---
    if (chatForm) {
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            const messageText = userInput.value.trim();
            if (messageText) {
                console.log('Mensaje enviado:', messageText);
                
                // Limpiar y reajustar
                userInput.value = '';
                adjustTextareaHeight();
                toggleSendButton();
            }
        });
    }
});