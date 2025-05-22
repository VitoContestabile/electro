const express = require('express');
const app = express();
const PORT = 3000;

// Servir archivos estáticos desde /public
app.use(express.static('public'));

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`);
});
