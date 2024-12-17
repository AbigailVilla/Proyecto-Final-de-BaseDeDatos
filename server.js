const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const multer = require('multer');
const xlsx = require('xlsx');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
require('dotenv').config();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'uploads', 'pdfs')); 
  },
  filename: (req, file, cb) => {
    const extname = path.extname(file.originalname); 
    cb(null, file.originalname);
  }
});
const uploadPDF = multer({ storage: storage });

timezone: 'America/Tijuana'

app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

app.use(express.urlencoded({ extended: true }));

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
      if (req.session.user && req.session.user.tipo_usuario === role) {
          next();
      } else {
          res.status(403).send('Acceso denegado');
      }
  };
}

function requireRole(roles) {
  return (req, res, next) => {
    if (req.session.user && roles.includes(req.session.user.tipo_usuario)) {
      next();
    } else {
      res.status(403).send('Acceso denegado');
    }
  };
}

app.get('/', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en funcionamiento en el puerto ${PORT}, da click aquí: http://localhost:3000`));

app.get('/usuarios', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'usuarios.html'));
});

app.get('/index', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/registro', (req, res) => {
  res.sendFile(__dirname + '/public/registro.html');
});

app.post('/registro', (req, res) => {
  const { nombre, apellidos, correo, password, nombreUsuario, codigo_acceso } = req.body;

  const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
  connection.query(query, [codigo_acceso], (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json({ message: 'Código de acceso inválido' });
    }

    const tipo_usuario = results[0].tipo_usuario;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ message: 'Error al encriptar la contraseña' });
      }

      const insertUser = 'INSERT INTO usuarios (nombre, apellidos, correo, contrasena, nombreUsuario, tipo_usuario) VALUES (?, ?, ?, ?, ?, ?)';
      connection.query(insertUser, [nombre, apellidos, correo, hashedPassword, nombreUsuario, tipo_usuario], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Error al registrar el usuario' });
        }

        res.redirect('/login.html');
      });
    });
  });
});

app.post('/registroUsuarios', (req, res) => {
  const { nombre, apellidos, correo, password, nombreUsuario, codigo_acceso } = req.body;

  // Verificar el código de acceso
  const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
  connection.query(query, [codigo_acceso], (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json({ message: 'Código de acceso inválido' });
    }

    const tipo_usuario = results[0].tipo_usuario;

    // Encriptar la contraseña
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ message: 'Error al encriptar la contraseña' });
      }

      // Insertar el usuario en la base de datos
      const insertUser = 'INSERT INTO usuarios (nombre, apellidos, correo, contrasena, nombreUsuario, tipo_usuario) VALUES (?, ?, ?, ?, ?, ?)';
      connection.query(insertUser, [nombre, apellidos, correo, hashedPassword, nombreUsuario, tipo_usuario], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Error al registrar el usuario' });
        }

        res.status(200).json({ message: 'Usuario registrado correctamente' });
      });
    });
  });
});

app.get('/usuarios', (req, res) => {
  const query = 'SELECT id, nombre, apellidos, correo FROM usuarios';
  connection.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error al obtener los usuarios' });
    }
    res.json(results);
  });
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/'); 
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html')); 
});

app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;

  const query = 'SELECT * FROM usuarios WHERE nombreUsuario = ?';
  connection.query(query, [nombre_usuario], (err, results) => {
    if (err) {
      return res.send('Error al obtener el usuario');
    }

    if (results.length === 0) {
      return res.send('Usuario no encontrado');
    }

    const user = results[0];

    const isPasswordValid = bcrypt.compareSync(password, user.contrasena);
    
    if (!isPasswordValid) {
      return res.send('Contraseña incorrecta');
    }
    req.session.user = user;
    res.redirect('/');  //
  });
});

app.get('/logout', requireLogin, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Error al cerrar sesión.');
    }
    res.redirect('/login');
  });
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/menu', requireLogin, (req, res) => {
  const userRole = req.session.user.tipo_usuario;
  let menuItems;

  if (userRole === 'admin') {
    menuItems = [
      { nombre: 'Inicio', url: '/index.html' },
      { nombre: 'Equipos', url: '/equipos.html' },
      { nombre: 'Usuarios', url: '/usuarios.html' },
      { nombre: 'Registros de cirugía', url: '/instrumentosMedicamentos.html' }
    ];
  } else if (userRole === 'medico') {
    menuItems = [
      { nombre: 'Inicio', url: '/index.html' },
      { nombre: 'Equipos', url: '/equipos.html' },
      { nombre: 'Registros de cirugía', url: '/instrumentosMedicamentos.html' }
    ];
  } else if (userRole === 'paciente') {
    menuItems = [
      { nombre: 'Inicio', url: '/index.html' },
      { nombre: 'Ver mis datos', url: '/ver-mis-datos' }
    ];
  } else {
    return res.status(403).send('Acceso denegado');
  }
  
  res.json(menuItems);
});

app.get('/ver-mis-datos', requireLogin, requireRole('paciente'), (req, res) => {
  const pacienteNombre = req.session.user.nombre; 
  const pacienteApellidos = req.session.user.apellidos; 

  const query = 'SELECT * FROM pacientes WHERE nombre = ? AND apellidos = ?';
  
  connection.query(query, [pacienteNombre, pacienteApellidos], (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos del paciente.');
    }

    if (results.length === 0) {
      return res.send('No se encontraron datos para este paciente.');
    }

    const paciente = results[0]; 

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Mis Datos</title>
      </head>
      <body>
        <h1>Mis Datos</h1>
        <table>
          <tr><th>Nombre</th><td>${paciente.nombre}</td></tr>
          <tr><th>Apellidos</th><td>${paciente.apellidos}</td></tr>
          <tr><th>Tipo de Sangre</th><td>${paciente.tipoSangre}</td></tr>
          <tr><th>Contacto de Emergencia</th><td>${paciente.contactoEmergencia}</td></tr>
          <tr><th>Alergias</th><td>${paciente.alergias}</td></tr>
          <tr><th>Departamento</th><td>${paciente.departamento_id}</td></tr>
          <tr><th>Estado de Salud</th><td>${paciente.estado}</td></tr>
        </table>
        <button onclick="window.location.href='/index.html'">Volver</button>
      </body>
      </html>
    `;
    res.send(html);
  });
});

app.get('/usuarios',  requireLogin, requireRole('admin'), (req, res) => {
  const sql = 'SELECT * FROM usuarios';
  connection.query(sql, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.post('/submit-data', requireLogin,  requireRole(['medico', 'admin', 'paciente']), (req, res) => {
  const { name, lastname, bloodtype, emergencynumber, allergies, dptid, condition } = req.body;

  const query = 'INSERT INTO pacientes (nombre, apellidos, tipoSangre, contactoEmergencia, alergias, departamento_id, estado) VALUES (?, ?, ?, ?, ?, ?, ?)';
  connection.query(query, [name, lastname, bloodtype, emergencynumber, allergies, dptid, condition ], (err, result) => {
    if (err) {
      return res.send('Error al guardar los datos en la base de datos.');
    }
    res.redirect('/index'); 
  });
});

app.get('/medicos', requireLogin, (req, res) => {
  const userRole = req.session.user.tipo_usuario;

  connection.query('SELECT * FROM medicos ORDER BY apellidos ASC', (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Medicos</title>
      </head>
      <body>
        <h1>Medicos registrados</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Apellidos</th>
              <th>Especialidad</th>
              ${userRole === 'admin' ? '<th>Salario</th>' : ''}
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(medico => {
      html += `
        <tr>
          <td>${medico.nombre}</td>
          <td>${medico.apellidos}</td>
          <td>${medico.especialidad}</td>
          ${userRole === 'admin' ? `<td>${medico.salario}</td>` : ''}
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    if (userRole === 'medico') {
      return res.send('Acceso denegado');
    }

    res.send(html);
  });
});

app.get('/buscar-pacientes', requireLogin, requireRole(['medico', 'admin']), (req, res) => {
  const { name_search, lastname_search } = req.query;
  let query = 'SELECT * FROM pacientes WHERE 1=1';

  if (name_search) {
    query += ` AND nombre LIKE '%${name_search}%'`;
  }
  if (lastname_search) {
    query += ` AND apellidos LIKE '%${lastname_search}%'`; 
  }

  connection.query(query, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Resultados de Búsqueda</title>
      </head>
      <body>
        <h1>Resultados de Búsqueda</h1>
        <table>
          <thead>
            <tr>
                <th>Nombre</th>
                <th>Apellidos</th>
                <th>Tipo de sangre</th>
                <th>Contacto de emergencia</th>
                <th>Alergias</th>
                <th>Planta para su consulta</th>
                <th>Estado de salud del paciente</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(paciente => {
      html += `
        <tr>
            <td>${paciente.nombre}</td>
            <td>${paciente.apellidos}</td>
            <td>${paciente.tipoSangre}</td>
            <td>${paciente.contactoEmergencia}</td>
            <td>${paciente.alergias}</td>
            <td>${paciente.departamento_id}</td>
            <td>${paciente.estado}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

app.get('/ordenar-pacientes', requireLogin, requireRole(['medico', 'admin']), (req, res) => {
  const query = 'SELECT * FROM pacientes ORDER BY apellidos ASC';

  connection.query(query, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Pacientes Ordenados</title>
      </head>
      <body>
        <h1>Pacientes</h1>
        <table>
          <thead>
            <tr>
                <th>Nombre</th>
                <th>Apellidos</th>
                <th>Tipo de sangre</th>
                <th>Contacto de emergencia</th>
                <th>Alergias</th>
                <th>Planta para su consulta</th>
                <th>Estado de salud del paciente</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.nombre}</td>
          <td>${paciente.apellidos}</td>
          <td>${paciente.tipoSangre}</td>
          <td>${paciente.contactoEmergencia}</td>
          <td>${paciente.alergias}</td>
          <td>${paciente.departamento_id}</td>
          <td>${paciente.estado}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

app.post('/insertar-medico', requireLogin, requireRole('admin'), (req, res) => {
  const { drname, drlastname, spec, salary} = req.body;

  const query = 'INSERT INTO medicos (nombre, apellidos, especialidad, salario) VALUES (?, ?, ?, ?)';
  connection.query(query, [drname, drlastname, spec, salary ], (err, result) => {
    if (err) {
      return res.send('Error al guardar los datos en la base de datos.');
    }
    res.redirect('/medicos');
  });
});

app.get('/buscar', requireLogin, requireRole('admin'), (req, res) => {
  const query = req.query.query;
  const sql = `SELECT nombre, apellidos, correo FROM usuarios WHERE nombre LIKE ?`;
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.post('/upload', requireLogin, requireRole('admin'), upload.single('excelFile'), (req, res) => {
  if (!req.file) {
    return res.send('No se ha subido ningún archivo.');
  }

  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  const filename = req.file.filename;  
  const sqlInsertFile = 'INSERT INTO archivos_excel (filename) VALUES (?)';
  connection.query(sqlInsertFile, [filename], err => {
    if (err) throw err;
  });

  data.forEach(row => {
    const { nombre, descripcion, tiempoUso, departamento } = row;
    const sql = `INSERT INTO equipos (nombre, descripcion, tiempoUso, departamento) VALUES (?, ?, ?, ?)`;
    connection.query(sql, [nombre, descripcion, tiempoUso, departamento], err => {
      if (err) throw err;
    });
  });

  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Confirmación de carga</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <div class="container">
        <h1>¡Archivo Excel cargado correctamente y datos guardados!</h1>
        <p class="mensaje-exito">El archivo ha sido procesado correctamente. Los datos se han guardado en la base de datos.</p>
        <div class="button-container">
          <button onclick="window.location.href='/equipos.html'" class="buttonv">Volver</button>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.post('/upload-pdf', requireLogin, requireRole('medico'), uploadPDF.single('pdfFile'), (req, res) => {
  if (!req.file) {
    return res.send('No se ha subido ningún archivo.');
  }
  const filename = req.file.filename;  
  const sqlInsertFile = 'INSERT INTO archivos_pdf (filename) VALUES (?)';
  connection.query(sqlInsertFile, [filename], err => {
    if (err) throw err;
  });

  console.log('Archivo PDF cargado:', filename);
  
  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Confirmación de carga</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <div class="container">
        <h1>¡Archivo PDF cargado correctamente!</h1>
        <p class="mensaje-exito">Tu archivo ha sido cargado correctamente. Puedes continuar con otras acciones.</p>
        <div class="button-container">
          <button onclick="window.location.href='/equipos.html'" class="buttonv">Volver</button>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.get('/instrumentosMedicamentos', requireLogin, requireRole(['medico', 'admin']), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'instrumentosMedicamentos.html'));
});

app.get('/instrumentosMedicamentos', requireLogin, (req, res) => {
  const userRole = req.session.user.tipo_usuario;
  const userId = req.session.user.id;

  if (userRole === 'paciente') {
    connection.query('SELECT * FROM pacientes WHERE id = ?', [userId], (err, results) => {
      if (err) {
        return res.status(500).send('Error al consultar la base de datos');
      }

      if (results.length === 0) {
        return res.status(404).send('Paciente no encontrado');
      }

      const paciente = results[0];
      res.render('instrumentosMedicamentos', {
        paciente: paciente
      });
    });
  } else {
    res.render('instrumentosMedicamentos', {
      paciente: null
    });
  }
});

app.post('/instrumentosMedicamentos', requireLogin, (req, res) => {
  const { patient, surgtype, time, surgroom, patientpre, patientpost, drlastname, instrument_name, instrument_description, instrument_quantity, medication_name, medication_description, medication_quantity } = req.body;
  const queryCirugia = 'INSERT INTO cirugias (paciente, tipo, duracionAprox, numQuirofano, estadoPacPre, estadoPacPost, apellidoDr) VALUES (?, ?, ?, ?, ?, ?, ?)';
  connection.query(queryCirugia, [patient, surgtype, time, surgroom, patientpre, patientpost, drlastname], (err, resultCirugia) => {
    if (err) {
      return res.send('Error al registrar la cirugía');
    }
    const cirugia_id = resultCirugia.insertId;
    const queryInstrumento = 'INSERT INTO instrumentosMedicamentos (nombreInstrumento, descripcionInstrumento, cantidadInstrumento, nombreMedicamento, descripcionMedicamento, cantidadMedicamento, cirugia_id) VALUES (?, ?, ?, ?, ?, ?, ?)';
    connection.query(queryInstrumento, [instrument_name, instrument_description, instrument_quantity, medication_name, medication_description, medication_quantity, cirugia_id], (err, resultInstrumento) => {
      if (err) {
        return res.send('Error al registrar los instrumentos y medicamentos');
      }
      res.redirect('/vista_registro_cirugia');
    });

  });
});

app.get('/vista_registro_cirugia', requireLogin, requireRole(['medico', 'admin']), (req, res) => {
  const sql = 'SELECT * FROM vista_registro_cirugia'; 
  connection.query(sql, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos de la vista');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Vista de Cirugías</title>
      </head>
      <body>
        <h1>Registros de cirugias, instrumentos y medicamentos</h1>
        <table>
          <thead>
            <tr>
              <th>Paciente</th>
              <th>Tipo de Cirugía</th>
              <th>Duración Aproximada</th>
              <th>Quirofano</th>
              <th>Estado Pre-Cirugía</th>
              <th>Estado Post-Cirugía</th>
              <th>Doctor</th>
              <th>Instrumento</th>
              <th>Descripción del Instrumento</th>
              <th>Cantidad del Instrumento</th>
              <th>Medicamento</th>
              <th>Descripción del Medicamento</th>
              <th>Cantidad del Medicamento</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(row => {
      html += `
        <tr>
          <td>${row.paciente}</td>
          <td>${row.tipo_cirugia}</td>
          <td>${row.duracionAprox}</td>
          <td>${row.numQuirofano}</td>
          <td>${row.estadoPacPre}</td>
          <td>${row.estadoPacPost}</td>
          <td>${row.apellidoDr}</td>
          <td>${row.nombreInstrumento}</td>
          <td>${row.descripcionInstrumento}</td>
          <td>${row.cantidadInstrumento}</td>
          <td>${row.nombreMedicamento}</td>
          <td>${row.descripcionMedicamento}</td>
          <td>${row.cantidadMedicamento}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/instrumentosMedicamentos'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

app.post('/register-equipo', requireLogin, requireRole('admin'), (req, res) => {
  const { nombre, descripcion, tiempoUso, departamento } = req.body;

  if (!nombre || !descripcion || !tiempoUso || !departamento) {
    return res.status(400).send('Todos los campos son obligatorios.');
  }

  const sql = 'INSERT INTO equipos (nombre, descripcion, tiempoUso, departamento) VALUES (?, ?, ?, ?)';
  connection.query(sql, [nombre, descripcion, tiempoUso, departamento], (err, result) => {
    if (err) {
      console.error('Error en la consulta SQL:', err); 
      return res.status(500).send('Error al registrar el equipo.');
    }
    res.redirect('/equipos.html'); 
  });
});

app.get('/buscar-equipos', requireLogin, requireRole(['medico', 'admin']), (req, res) => {
  const searchTerm = req.query.search;
  const query = 'SELECT * FROM equipos WHERE nombre LIKE ? OR descripcion LIKE ?';
  
  connection.query(query, [`%${searchTerm}%`, `%${searchTerm}%`], (err, results) => {
    if (err) {
      return res.status(500).send('Error al buscar los equipos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Resultados de Búsqueda</title>
      </head>
      <body>
        <h1>Resultados de Búsqueda</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Descripción</th>
              <th>Tiempo de Uso</th>
              <th>Departamento</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(equipo => {
      html += `
        <tr>
          <td>${equipo.nombre}</td>
          <td>${equipo.descripcion}</td>
          <td>${equipo.tiempoUso}</td>
          <td>${equipo.departamento}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/equipos.html'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

app.get('/archivos-cargados', requireLogin, requireRole('admin'), (req, res) => {
  const pdfFilesQuery = 'SELECT filename FROM archivos_pdf';
  connection.query(pdfFilesQuery, (err, pdfFilesResults) => {
    if (err) throw err;
    const excelFilesQuery = 'SELECT filename FROM archivos_excel';
    connection.query(excelFilesQuery, (err, excelFilesResults) => {
      if (err) throw err;

      res.json({
        isAdmin: true, 
        pdfFiles: pdfFilesResults.map(file => file.filename),
        excelFiles: excelFilesResults.map(file => file.filename)
      });
    });
  });
});

app.post('/upload-pdf', requireLogin, requireRole('medico'), uploadPDF.single('pdfFile'), (req, res) => {
  if (!req.file) {
    return res.send('No se ha subido ningún archivo.');
  }

  const filePath = req.file.path; 
  const filename = req.file.filename; 

  const sql = 'INSERT INTO archivos_pdf (filename) VALUES (?)';
  connection.query(sql, [filename], err => {
    if (err) throw err;

    console.log('Archivo PDF cargado:', filePath);
    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Confirmación de carga</title>
        <link rel="stylesheet" href="styles.css">
      </head>
      <body>
        <div class="container">
          <h1>¡Archivo PDF cargado correctamente!</h1>
          <p class="mensaje-exito">Tu archivo ha sido cargado correctamente. Puedes continuar con otras acciones.</p>
          <div class="button-container">
            <button onclick="window.location.href='/equipos.html'" class="buttonv">Volver</button>
          </div>
        </div>
      </body>
      </html>
    `);
  });
});

app.post('/upload', requireLogin, requireRole('admin'), upload.single('excelFile'), (req, res) => {
  if (!req.file) {
    return res.send('No se ha subido ningún archivo.');
  }

  const filePath = req.file.path;
  const filename = req.file.filename; 

  const sql = 'INSERT INTO archivos_excel (filename) VALUES (?)';
  connection.query(sql, [filename], err => {
    if (err) throw err;

    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    data.forEach(row => {
      const { nombre, descripcion, tiempoUso, departamento } = row;
      const sqlInsert = `INSERT INTO equipos (nombre, descripcion, tiempoUso, departamento) VALUES (?, ?, ?, ?)`;
      connection.query(sqlInsert, [nombre, descripcion, tiempoUso, departamento], err => {
        if (err) throw err;
      });
    });

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Confirmación de carga</title>
        <link rel="stylesheet" href="styles.css">
      </head>
      <body>
        <div class="container">
          <h1>¡Archivo Excel cargado correctamente y datos guardados!</h1>
          <p class="mensaje-exito">El archivo ha sido procesado correctamente. Los datos se han guardado en la base de datos.</p>
          <div class="button-container">
            <button onclick="window.location.href='/equipos.html'" class="buttonv">Volver</button>
          </div>
        </div>
      </body>
      </html>
    `);
  });
});

app.get('/download-pdf/:filename', requireLogin, requireRole('admin'), (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', 'pdfs', filename); 

  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).send('Archivo no encontrado.');
    }

    res.type('pdf'); 
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');

    res.download(filePath, filename, (err) => {
      if (err) {
        return res.status(404).send('Error al descargar el archivo.');
      }
    });
  });
});

app.get('/download', (req, res) => {
  const sql = `SELECT * FROM equipos`;
  connection.query(sql, (err, results) => {
    if (err) throw err;

    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'Equipos');

    const filePath = path.join(__dirname, 'uploads', 'equipos.xlsx');
    xlsx.writeFile(workbook, filePath);
    res.download(filePath, 'equipos.xlsx');
  });
});

app.get('/medicos-por-departamento', requireLogin, (req, res) => {
  const userRole = req.session.user.tipo_usuario;

  connection.query(
    'SELECT especialidad, nombre, apellidos FROM medicos ORDER BY especialidad, nombre ASC',
    (err, results) => {
      if (err) {
        return res.send('Error al obtener los datos.');
      }

      let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/styles.css">
          <title>Médicos por Departamento</title>
        </head>
        <body>
          <h1>Médicos por Especialidad</h1>
          <table>
            <thead>
              <tr>
                <th>Especialidad</th>
                <th>Médicos</th>
              </tr>
            </thead>
            <tbody>
      `;
      let currentEspecialidad = '';
      let doctorsList = '';
      results.forEach(medico => {
        if (medico.especialidad !== currentEspecialidad) {
          if (currentEspecialidad !== '') {
            html += `
              <tr>
                <td>${currentEspecialidad}</td>
                <td><ul>${doctorsList}</ul></td>
              </tr>
            `;
          }

          currentEspecialidad = medico.especialidad;
          doctorsList = `<li>${medico.nombre} ${medico.apellidos}</li>`;
        } else {
          doctorsList += `<li>${medico.nombre} ${medico.apellidos}</li>`;
        }
      });

      html += `
        <tr>
          <td>${currentEspecialidad}</td>
          <td><ul>${doctorsList}</ul></td>
        </tr>
      `;

      html += `
            </tbody>
          </table>
          <button onclick="window.location.href='/'">Volver</button>
        </body>
        </html>
      `;

      if (userRole === 'medico') {
        return res.send('Acceso denegado');
      }

      res.send(html);
    }
  );
});
