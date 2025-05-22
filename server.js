const express = require('express');
const { Client } = require('pg');
const app = express();
const PORT = 3000;

// --- Configuración PostgreSQL ---
const db = new Client({
  host: '172.31.62.36',
  user: 'messi',
  password: 'trubenja38',
  database: 'mqttdata',
  port: 5432
});

// Conectar a la base de datos
db.connect()
  .then(() => {
    console.log('✅ Conectado a PostgreSQL');
  })
  .catch(err => {
    console.error('❌ Error conectando a PostgreSQL:', err);
  });

// Middleware para parsear JSON
app.use(express.json());

// Servir archivos estáticos desde /public
app.use(express.static('public'));

// Ruta de ejemplo para probar la conexión a la DB
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await db.query('SELECT NOW() as current_time');
    res.json({
      success: true,
      message: 'Conexión a DB exitosa',
      data: result.rows[0]
    });
  } catch (error) {
    console.error('Error en consulta DB:', error);
    res.status(500).json({
      success: false,
      message: 'Error conectando a la base de datos',
      error: error.message
    });
  }
});

// Manejo de cierre graceful
process.on('SIGINT', async () => {
  console.log('\n🔄 Cerrando servidor...');
  await db.end();
  console.log('✅ Conexión a DB cerrada');
  process.exit(0);
});

// Iniciar servidor
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor escuchando en http://0.0.0.0:${PORT}`);
});