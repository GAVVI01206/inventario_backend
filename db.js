require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error al conectar con la base de datos:', err.stack);
    }
    console.log('¡Conexión exitosa a CockroachDB, brou!');
    release();
});

module.exports = pool;