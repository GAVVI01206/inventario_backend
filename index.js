const express = require('express');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const pool = require('./db');

const app = express();
// Configuración de Nodemailer para enviar correos
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
// Middlewares obligatorios
app.use(cors());
app.use(express.json());

// Middleware: Protección de rutas requerida por el taller
const verificarToken = (req, res, next) => {
    // El token debe venir en los headers de la petición
    const bearerHeader = req.header('Authorization');
    
    if (!bearerHeader) {
        return res.status(401).json({ error: 'Acceso denegado. Se necesita un token.' });
    }

    try {
        // Extraemos el token quitando la palabra "Bearer "
        const token = bearerHeader.split(" ")[1];
        const verificado = jwt.verify(token, process.env.JWT_SECRET);
        
        // Guardamos los datos del usuario (id y rol) para usarlos en la ruta
        req.usuario = verificado;
        next(); // El guardia te deja pasar
    } catch (error) {
        res.status(400).json({ error: 'Token no válido o expirado.' });
    }
};
// Requisito: Registro de usuarios con contraseña en Hash
app.post('/api/registro', async (req, res) => {
    try {
        const { nombre, email, password, rol } = req.body;

        // 1. Encriptar la contraseña (Salt de 10 rondas es el estándar seguro)
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // 2. Insertar en CockroachDB
        const nuevoUsuario = await pool.query(
            'INSERT INTO usuarios (nombre, email, password_hash, rol) VALUES ($1, $2, $3, $4) RETURNING id, nombre, email, rol',
            [nombre, email, passwordHash, rol || 'auxiliar']
        );

        res.status(201).json({
            mensaje: 'Usuario creado exitosamente',
            usuario: nuevoUsuario.rows[0]
        });

    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Error en el servidor. Puede que el correo ya esté registrado.' });
    }
});

// Requisito: Consultar lista de productos
app.get('/api/productos', verificarToken, async (req, res) => {
    try {
        const productos = await pool.query('SELECT * FROM productos ORDER BY id DESC');
        res.json(productos.rows);
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Error al obtener los productos' });
    }
});
// Requisito: Inicio de sesión y generación de Token
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Verificar si el usuario existe en la base de datos
        const usuario = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (usuario.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        // 2. Comparar la contraseña enviada con el hash guardado
        const validPassword = await bcrypt.compare(password, usuario.rows[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        // 3. Generar el Token de acceso protegido
        const token = jwt.sign(
            { id: usuario.rows[0].id, rol: usuario.rows[0].rol },
            process.env.JWT_SECRET,
            { expiresIn: '2h' } // El token expira en 2 horas
        );

        res.json({
            mensaje: 'Inicio de sesión exitoso',
            token: token
        });

    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Error en el servidor durante el login' });
    }
});

// Requisito: Operación CRUD (Crear producto) en ruta protegida
app.post('/api/productos', verificarToken, async (req, res) => {
    try {
        const { nombre, unidad_medida, precio_unitario, stock_actual } = req.body;

        const nuevoProducto = await pool.query(
            'INSERT INTO productos (nombre, unidad_medida, precio_unitario, stock_actual) VALUES ($1, $2, $3, $4) RETURNING *',
            [nombre, unidad_medida, precio_unitario, stock_actual || 0]
        );

        res.status(201).json({
            mensaje: 'Producto agregado al inventario exitosamente',
            producto: nuevoProducto.rows[0]
        });

    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Error al crear el producto' });
    }
});
// Requisito: Flujo 1 - Solicitar recuperación de contraseña
app.post('/api/olvido-password', async (req, res) => {
    const { email } = req.body;
    try {
        const usuario = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (usuario.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Generar un token único y seguro de 64 caracteres
        const resetToken = crypto.randomBytes(32).toString('hex');
        // El token expira en 1 hora
      // Guardar el token temporal y dejar que la base de datos calcule la hora exacta (+1 hora)
        await pool.query(
            "UPDATE usuarios SET reset_token = $1, reset_token_expires = current_timestamp() + INTERVAL '1 hour' WHERE email = $2",
            [resetToken, email]
        );

        // Enviar el correo al usuario
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Recuperación de Contraseña - Sistema de Inventario',
            html: `<h2>¿Olvidaste tu contraseña?</h2>
                   <p>No te preocupes, usa este token temporal para restablecerla:</p>
                   <h3><b>${resetToken}</b></h3>
                   <p>Cópialo y pégalo en el sistema. Este código expirará en 1 hora.</p>`
        };

        await transporter.sendMail(mailOptions);
        res.json({ mensaje: 'Correo de recuperación enviado exitosamente, revisa tu bandeja de entrada' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al enviar el correo' });
    }
});

// Requisito: Flujo 2 - Actualizar contraseña con el token
app.post('/api/reset-password', async (req, res) => {
    const { token, nuevaPassword } = req.body;
    try {
        // Verificar si el token es real y si aún no ha expirado
        const usuario = await pool.query(
            'SELECT * FROM usuarios WHERE reset_token = $1 AND reset_token_expires > current_timestamp()',
            [token]
        );

        if (usuario.rows.length === 0) {
            return res.status(400).json({ error: 'Token inválido o ya expiró' });
        }

        // Hashear la NUEVA contraseña
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(nuevaPassword, salt);

        // Actualizar la base de datos y destruir el token para que no se pueda reusar
        await pool.query(
            'UPDATE usuarios SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
            [passwordHash, usuario.rows[0].id]
        );

        res.json({ mensaje: '¡Contraseña actualizada exitosamente en la BD!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al restablecer la contraseña' });
    }
});

// Requisito: Generación de reporte dinámico en PDF
app.get('/api/reportes/pdf', async (req, res) => {
    try {
        const productos = await pool.query('SELECT * FROM productos');
        
        const doc = new PDFDocument();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename=reporte_inventario.pdf');
        doc.pipe(res);

        // Cumplimiento de estructura obligatoria del taller
        doc.fontSize(20).text('Reporte de Inventario - Restaurante', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).text(`Fecha de generación: ${new Date().toLocaleString()}`);
        doc.text(`ID del Reporte: REP-${Math.floor(Math.random() * 10000)}`);
        doc.moveDown();

        doc.fontSize(14).text('Información de Productos Consultada de BD:', { underline: true });
        doc.moveDown();

        // Imprimir cada producto registrado
        productos.rows.forEach((prod, index) => {
            doc.fontSize(12).text(`${index + 1}. Producto: ${prod.nombre} | Stock: ${prod.stock_actual} ${prod.unidad_medida} | Precio: $${prod.precio_unitario}`);
        });

        doc.end();
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al generar el PDF' });
    }
});

// Requisito: Generación de reporte dinámico en EXCEL
app.get('/api/reportes/excel', async (req, res) => {
    try {
        const productos = await pool.query('SELECT * FROM productos');
        
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Inventario');

        // Cumplimiento de estructura obligatoria del taller
        worksheet.columns = [
            { header: 'ID Reporte', key: 'id_rep', width: 15 },
            { header: 'Fecha', key: 'fecha', width: 25 },
            { header: 'Nombre Producto', key: 'nombre', width: 30 },
            { header: 'Stock', key: 'stock', width: 15 },
            { header: 'Medida', key: 'medida', width: 15 },
            { header: 'Precio Unitario', key: 'precio', width: 20 }
        ];

        const fechaGeneracion = new Date().toLocaleString();
        const idReporte = `REP-${Math.floor(Math.random() * 10000)}`;

        // Llenar las filas con la información de la base de datos
        productos.rows.forEach(prod => {
            worksheet.addRow({
                id_rep: idReporte,
                fecha: fechaGeneracion,
                nombre: prod.nombre,
                stock: prod.stock_actual,
                medida: prod.unidad_medida,
                precio: prod.precio_unitario
            });
        });

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=reporte_inventario.xlsx');

        await workbook.xlsx.write(res);
        res.end();
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al generar el Excel' });
    }
});
// Levantar el servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`¡Servidor del inventario corriendo en el puerto ${PORT}, brou!`);
});