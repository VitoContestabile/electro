const express = require('express');
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mqtt = require('mqtt');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());

// Configuración JWTa
const JWT_SECRET = 'tu_clave_secreta_super_segura_cambiala_en_produccion';
const JWT_EXPIRES_IN = '24h';

// --- Configuración PostgreSQL ---
const db = new Client({
  host: '172.31.62.36',
  user: 'messi',
  password: 'trubenja38',
  database: 'mqttdata',
  port: 5432
});

// Variables para MQTT
let ultimaCorriente1 = null;
let ultimaCorriente2 = null;
let tiempoUltimoInsert = 0;
const intervaloInsercion = 5000; // 5 segundos


// Conectar a la base de datos
db.connect()
  .then(() => {
    console.log('✅ Conectado a PostgreSQL');
    initializeDatabase();
  })
  .catch(err => {
    console.error('❌ Error conectando a PostgreSQL:', err);
  });

// Crear tablas si no existen
async function initializeDatabase() {
  try {
    // Tabla de usuarios
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Tabla de usuarios lista');

    // Tabla de corrientes
    await db.query(`
      CREATE TABLE IF NOT EXISTS corrientes (
        id SERIAL PRIMARY KEY,
        corriente1 FLOAT,
        corriente2 FLOAT,
        fecha TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log('✅ Tabla de corrientes lista');

  } catch (error) {
    console.error('❌ Error creando tablas:', error);
  }
}

// --- Configuración MQTT ---
const mqttClient = mqtt.connect('mqtt://localhost:1883');

mqttClient.on('connect', () => {
  console.log('✅ Conectado a broker MQTT');
  mqttClient.subscribe(['XJXT06/corriente1', 'XJXT06/corriente2'], (err) => {
    if (err) {
      console.error('❌ Error al suscribirse:', err);
    } else {
      console.log('✅ Suscripto a los topics MQTT');
    }
  });
});

mqttClient.on('message', (topic, message) => {
  const valor = parseFloat(message.toString());
  if (isNaN(valor)) {
    console.warn('⚠️ Valor inválido recibido:', message.toString());
    return;
  }

  const ahora = Date.now();

  if (topic === 'XJXT06/corriente1') {
    ultimaCorriente1 = valor;
    console.log(`📊 corriente1: ${valor} A`);
  } else if (topic === 'XJXT06/corriente2') {
    ultimaCorriente2 = valor;
    console.log(`📊 corriente2: ${valor} A`);
  }

  // Insertar si pasaron más de 5 segundos desde el último insert
  if (ahora - tiempoUltimoInsert > intervaloInsercion) {
    insertarEnDB();
    tiempoUltimoInsert = ahora;
  }
});

function insertarEnDB() {
  const query = `
    INSERT INTO corrientes (corriente1, corriente2)
    VALUES ($1, $2)
  `;

  db.query(query, [ultimaCorriente1, ultimaCorriente2])
    .then(() => console.log('💾 Datos de corriente guardados en la base de datos'))
    .catch(err => console.error('❌ Error al guardar corrientes en la base:', err));
}

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Middleware para verificar JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token de acceso requerido'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Token inválido o expirado'
      });
    }
    req.user = user;
    next();
  });
};

// --- ENDPOINTS DE CORRIENTES (PROTEGIDOS) ---

// Obtener datos actuales de corriente
app.get('/api/corrientes/current', authenticateToken, (req, res) => {
  res.json({
    success: true,
    data: {
      corriente1: ultimaCorriente1,
      corriente2: ultimaCorriente2,
      timestamp: new Date().toISOString()
    }
  });
});

// Obtener historial de corrientes
app.get('/api/corrientes/history', authenticateToken, async (req, res) => {
  try {
    const { limit = 100, offset = 0 } = req.query;

    const result = await db.query(
      'SELECT * FROM corrientes ORDER BY fecha DESC LIMIT $1 OFFSET $2',
      [parseInt(limit), parseInt(offset)]
    );

    res.json({
      success: true,
      data: {
        records: result.rows,
        total: result.rowCount
      }
    });

  } catch (error) {
    console.error('Error obteniendo historial de corrientes:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// Obtener estadísticas de corrientes
app.get('/api/corrientes/stats', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT 
        COUNT(*) as total_registros,
        AVG(corriente1) as promedio_corriente1,
        AVG(corriente2) as promedio_corriente2,
        MAX(corriente1) as max_corriente1,
        MAX(corriente2) as max_corriente2,
        MIN(corriente1) as min_corriente1,
        MIN(corriente2) as min_corriente2,
        MIN(fecha) as primer_registro,
        MAX(fecha) as ultimo_registro
      FROM corrientes
    `);

    res.json({
      success: true,
      data: result.rows[0]
    });

  } catch (error) {
    console.error('Error obteniendo estadísticas:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});


// --- ENDPOINTS DE AUTENTICACIÓN ---

// Registro de usuario
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validaciones básicas
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email y password son requeridos'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'La contraseña debe tener al menos 6 caracteres'
      });
    }

    // Verificar si el usuario ya existe
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Usuario o email ya registrado'
      });
    }

    // Hashear la contraseña
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insertar nuevo usuario
    const result = await db.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, email, passwordHash]
    );

    const newUser = result.rows[0];

    // Generar JWT
    const token = jwt.sign(
      {
        userId: newUser.id,
        username: newUser.username,
        email: newUser.email
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({
      success: true,
      message: 'Usuario registrado exitosamente',
      data: {
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
          created_at: newUser.created_at
        },
        token
      }
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// Login de usuario
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validaciones básicas
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username y password son requeridos'
      });
    }

    // Buscar usuario (por username o email)
    const result = await db.query(
      'SELECT id, username, email, password_hash, created_at FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    const user = result.rows[0];

    // Verificar contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas'
      });
    }

    // Generar JWT
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      success: true,
      message: 'Login exitoso',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          created_at: user.created_at
        },
        token
      }
    });

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// --- RUTAS PROTEGIDAS ---

// Perfil de usuario (requiere autenticación)
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, username, email, created_at FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    res.json({
      success: true,
      data: {
        user: result.rows[0]
      }
    });

  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// Verificar token
app.get('/api/verify-token', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Token válido',
    data: {
      user: {
        userId: req.user.userId,
        username: req.user.username,
        email: req.user.email
      }
    }
  });
});

// --- OTRAS RUTAS ---

// Ruta de prueba de DB
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


// Variables para almacenar el estado actual de los relés
let estadoReles = {
  rele1: 'OFF',
  rele2: 'OFF'
};

// Escuchar mensajes MQTT para actualizar el estado
mqttClient.on('message', (topic, message) => {
  const messageStr = message.toString();

  // Actualizar estado de relé 1
  if (topic === 'XJXT06/rele1') {
    estadoReles.rele1 = messageStr;
    console.log(`🔄 Estado Relé 1 actualizado: ${messageStr}`);
  }

  // Actualizar estado de relé 2
  if (topic === 'XJXT06/rele2') {
    estadoReles.rele2 = messageStr;
    console.log(`🔄 Estado Relé 2 actualizado: ${messageStr}`);
  }
});

// Suscribirse a los topics de estado al conectar
mqttClient.on('connect', () => {
  console.log('✅ Conectado al broker MQTT');

  // Suscribirse a los topics de estado
  mqttClient.subscribe('XJXT06/rele1', (err) => {
    if (err) {
      console.error('❌ Error suscribiéndose a XJXT06/rele1:', err);
    } else {
      console.log('✅ Suscrito a XJXT06/rele1');
    }
  });

  mqttClient.subscribe('XJXT06/rele2', (err) => {
    if (err) {
      console.error('❌ Error suscribiéndose a XJXT06/rele2:', err);
    } else {
      console.log('✅ Suscrito a XJXT06/rele2');
    }
  });
});

// NUEVO ENDPOINT: Obtener estado de los relés
app.get('/api/reles/estado', authenticateToken, (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        rele1: estadoReles.rele1,
        rele2: estadoReles.rele2
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error obteniendo estado de relés:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

// Tu endpoint existente de control (sin cambios)
app.post('/api/rele', authenticateToken, (req, res) => {
  try {
    const { rele, estado } = req.body;

    // Validaciones básicas
    if (!rele || !estado) {
      return res.status(400).json({
        success: false,
        message: 'Relé y estado son requeridos'
      });
    }

    // Validar que el relé sea un número válido (1 o 2)
    const releNum = parseInt(rele);
    if (isNaN(releNum) || releNum < 1 || releNum > 2) {
      return res.status(400).json({
        success: false,
        message: 'El relé debe ser 1 o 2'
      });
    }

    // Validar que el estado sea válido
    if (estado !== 'ON' && estado !== 'OFF') {
      return res.status(400).json({
        success: false,
        message: 'El estado debe ser ON u OFF'
      });
    }

    // Construir el topic correctamente
    const topic = `XJXT06/control${releNum}`;
    const mensaje = estado;

    // Publicar mensaje MQTT
    mqttClient.publish(topic, mensaje, (err) => {
      if (err) {
        console.error('❌ Error al publicar mensaje MQTT:', err);
        return res.status(500).json({
          success: false,
          message: 'Error al enviar comando al dispositivo'
        });
      }

      console.log(`🟡 Enviado a ${topic}: ${mensaje}`);
      res.json({
        success: true,
        message: `Relé ${releNum} ${estado === 'ON' ? 'encendido' : 'apagado'} correctamente`,
        data: {
          rele: releNum,
          estado: estado,
          topic: topic
        }
      });
    });

  } catch (error) {
    console.error('Error en control de relé:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});