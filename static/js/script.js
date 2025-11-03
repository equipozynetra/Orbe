document.addEventListener('DOMContentLoaded', () => {

    const orbContainer = document.getElementById('orb-container');
    const backgroundMusic = document.getElementById('background-music');
    backgroundMusic.volume = 0.1; // Ajusta el volumen (0.0 a 1.0)

    // --- LÓGICA PARA EL MOVIMIENTO DEL ORBE CON EL RATÓN ---
    if (window.matchMedia("(pointer: fine)").matches) {
        document.body.addEventListener('mousemove', (e) => {
            const x = (e.clientX / window.innerWidth) - 0.5;
            const y = (e.clientY / window.innerHeight) - 0.5;
            const movementStrength = 25; 
            const rotateX = -y * movementStrength;
            const rotateY = x * movementStrength;
            orbContainer.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });
    }

    // --- LÓGICA PARA LA MÚSICA DE FONDO ---
    // Función para intentar reproducir la música
    const playMusic = async () => {
        try {
            await backgroundMusic.play();
            // Si la reproducción es exitosa, removemos el 'listener' para no volver a intentarlo.
            document.body.removeEventListener('click', playMusicOnClick);
        } catch (error) {
            // El autoplay fue bloqueado, el usuario necesita interactuar.
            console.log("Autoplay de música bloqueado. Esperando interacción del usuario.");
        }
    };

    // Un listener que se activará con el primer clic del usuario
    const playMusicOnClick = () => {
        playMusic();
    };

    document.body.addEventListener('click', playMusicOnClick, { once: true });
    
    // Intentamos reproducir la música al cargar, por si el navegador lo permite
    playMusic();
});